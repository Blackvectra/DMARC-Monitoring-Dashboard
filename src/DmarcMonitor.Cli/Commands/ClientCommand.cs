using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Onboarding: turning domains that reports arrived for into clients.
///
/// Reports are stored under an "Unassigned" client rather than being refused,
/// because a report that arrives before anybody has onboarded the domain is
/// still evidence and cannot be fetched again later. That makes Unassigned a
/// worklist, and this is what empties it.
/// </summary>
public static class ClientCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--name", "--slug", "--org", "--domain", "--client", "--group", "--by", "--confirm", "!--apply") is var bad and not 0) { return bad; }

        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        // The organization new clients belong to. Everything else here names
        // a client or a domain by slug, which is unique across organizations.
        var store = new ReportStore(dbPath, Args.Value(rest, "--org") ?? ReportStore.DefaultTenantSlug);
        if (!await store.IsInitializedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        return action switch
        {
            "list" => await ListAsync(store, ct).ConfigureAwait(false),
            "add" => await AddAsync(store, rest, ct).ConfigureAwait(false),
            "assign" => await AssignAsync(store, dbPath, rest, ct).ConfigureAwait(false),
            "auto-assign" => await AutoAssignAsync(dbPath, rest, ct).ConfigureAwait(false),
            "set-group" => await SetGroupAsync(store, rest, ct).ConfigureAwait(false),
            "erase" => await EraseAsync(dbPath, rest, ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc client {action}"),
        };
    }

    /// <summary>
    /// The customer's own login: members of the group see this client and
    /// nothing else, read only.
    /// </summary>
    private static async Task<int> SetGroupAsync(ReportStore store, string[] args, CancellationToken ct)
    {
        var client = Args.Value(args, "--client");
        if (string.IsNullOrWhiteSpace(client))
        {
            return Usage("dmarc client set-group --client <slug> --group <entra group object id> [--db <path>]   (omit --group to clear it)");
        }

        var group = Args.Value(args, "--group");
        if (!await store.SetClientGroupAsync(client, group, ct: ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"No client with the slug '{client}'. See: dmarc client list");
            return 66;
        }

        Console.WriteLine(string.IsNullOrWhiteSpace(group)
            ? $"'{client}' has no customer login group now."
            : $"Members of {group.Trim()} see '{client}' and nothing else, read only. They may need to sign out and back in.");
        return 0;
    }

    private static async Task<int> ListAsync(ReportStore store, CancellationToken ct)
    {
        var clients = await store.GetClientsAsync(ct: ct).ConfigureAwait(false);
        if (clients.Count == 0)
        {
            Console.WriteLine("No clients yet. Import some reports first, then: dmarc client add --name \"<name>\"");
            return 0;
        }

        // The organization column only earns its width once there are two.
        var organizations = clients.Select(c => c.OrganizationSlug).Distinct(StringComparer.Ordinal).Count() > 1;

        Console.WriteLine();
        Console.WriteLine($"  {"slug",-28} {"name",-32} {"domains",7} {"messages",9}{(organizations ? "  organization" : "")}");
        foreach (var c in clients)
        {
            Console.WriteLine($"  {c.Slug,-28} {c.Name,-32} {c.Domains,7} {c.Messages,9:N0}{(organizations ? "  " + c.OrganizationSlug : "")}");
        }

        var unassigned = await store.GetUnassignedDomainsAsync(ct: ct).ConfigureAwait(false);
        if (unassigned.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"  {unassigned.Count} domain(s) still unassigned:");
            foreach (var d in unassigned) { Console.WriteLine($"    {d}"); }
            Console.WriteLine();
            Console.WriteLine("  dmarc client assign --domain <domain> --client <slug>");
        }

        Console.WriteLine();
        return 0;
    }

    private static async Task<int> AddAsync(ReportStore store, string[] args, CancellationToken ct)
    {
        var name = Args.Value(args, "--name");
        if (string.IsNullOrWhiteSpace(name))
        {
            return Usage("dmarc client add --name \"<name>\" [--slug <slug>] [--org <organization slug>] [--db <path>]");
        }

        var slug = await store.CreateClientAsync(name, Args.Value(args, "--slug"), store.Organization, ct).ConfigureAwait(false);
        if (slug is null)
        {
            // Either the name reduced to nothing usable, or it is taken. Both
            // are worth distinguishing, because the fix differs.
            var wanted = ReportStore.Slugify(Args.Value(args, "--slug") ?? name);
            Console.Error.WriteLine(wanted.Length == 0
                ? $"'{name}' has no letters or digits to make a slug from. Pass --slug <slug>."
                : $"A client with the slug '{wanted}' already exists. Pass --slug <slug> to pick another.");
            return 65;
        }

        Console.WriteLine($"Added {name} as '{slug}'.");
        Console.WriteLine($"Next: dmarc client assign --domain <domain> --client {slug}");
        return 0;
    }

    /// <summary>
    /// Files every unassigned domain under a client named after it.
    /// </summary>
    /// <remarks>
    /// Onboarding one domain at a time is the honest way to do it, because a
    /// client is a billing relationship and only a person knows which domains
    /// belong together. This is for the other case: a book of domains where
    /// each one IS its own customer, and typing eighteen pairs of commands is
    /// the only thing standing between an import and a usable set of reports.
    ///
    /// The client is named after the domain exactly - mortonnd.gov is filed
    /// as "mortonnd.gov", slug "mortonnd-gov" - so the mapping is one to one
    /// and obvious. That matters later: when a real client name is known, it
    /// is clear which placeholder it replaces, and two domains can never
    /// collide onto one slug by accident. The slug is permanent because it
    /// ends up in report filenames, so a dry run prints the whole mapping
    /// first and nothing is written until --apply.
    /// </remarks>
    private static async Task<int> AutoAssignAsync(string dbPath, string[] args, CancellationToken ct)
    {
        var apply = Args.Flag(args, "--apply");

        // One organization at a time, each domain filed in the organization
        // it already belongs to. This used to list every organization's
        // unassigned domains together, create the client in whichever
        // organization --org named (Local, by default), and assign with no
        // tenant - which moved a second organization's domain, and its whole
        // history, into the first organization's tenant. Auto-assign is a
        // filing command; it never changes whose domain something is.
        var organizations = await new OrganizationStore(dbPath).ListAsync(ct).ConfigureAwait(false);
        var wanted = Args.Value(args, "--org");
        if (!string.IsNullOrWhiteSpace(wanted))
        {
            organizations = [.. organizations.Where(o => o.Slug.Equals(wanted, StringComparison.OrdinalIgnoreCase))];
            if (organizations.Count == 0)
            {
                Console.Error.WriteLine($"No organization called '{wanted}'. Run: dmarc org list");
                return 66;
            }
        }

        var totalPlanned = 0;
        var totalFiled = 0;
        var anyDomains = false;

        foreach (var organization in organizations)
        {
            var store = new ReportStore(dbPath, organization.Slug);
            var domains = await store.GetUnassignedDomainsAsync(organization.Id, ct).ConfigureAwait(false);
            if (domains.Count == 0) { continue; }
            anyDomains = true;

            var (planned, filed) = await AutoAssignOrganizationAsync(store, organization, domains, apply, ct).ConfigureAwait(false);
            totalPlanned += planned;
            totalFiled += filed;
        }

        if (!anyDomains)
        {
            Console.WriteLine("Every domain is already filed under a client.");
            return 0;
        }

        if (!apply)
        {
            Console.WriteLine($"  {totalPlanned} domain(s) would be filed. Nothing has been written.");
            Console.WriteLine("  The slug goes into report filenames and cannot be changed afterwards.");
            Console.WriteLine("  Run it for real:  dmarc client auto-assign --apply");
            Console.WriteLine();
            return 0;
        }

        Console.WriteLine($"  {totalFiled} domain(s) filed.");
        Console.WriteLine("  Check it: dmarc client list");
        Console.WriteLine();
        return totalFiled == totalPlanned ? 0 : 65;
    }

    private static async Task<(int Planned, int Filed)> AutoAssignOrganizationAsync(
        ReportStore store, Organization organization, IReadOnlyList<string> domains, bool apply, CancellationToken ct)
    {
        Console.WriteLine();
        Console.WriteLine($"  {organization.Name} ({organization.Slug})");
        Console.WriteLine($"  {"domain",-26} {"client",-26} {"slug",-24}");

        // Built a name at a time rather than with ToDictionary, because a slug
        // is unique within an organization and not across them: every
        // organization carries its own Unassigned, filed under that same slug.
        //
        // ToDictionary threw on the second one - "An item with the same key
        // has already been added. Key: unassigned" - as an unhandled
        // exception with a stack trace, so auto-assign stopped working
        // entirely the moment a second organization existed. That is the
        // shape this product is for, and the crash was in the one command
        // meant to save an operator from typing eighteen pairs of commands.
        //
        // This is only a collision check for the slugs about to be created,
        // and those all go into one organization, so one name per slug is
        // enough.
        var taken = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var client in await store.GetClientsAsync(organization.Id, ct).ConfigureAwait(false))
        {
            taken[client.Slug] = client.Name;
        }

        var planned = new List<(string Domain, string Name, string Slug)>();
        foreach (var domain in domains)
        {
            var name = domain;
            var slug = ReportStore.Slugify(domain);

            // Nothing should be able to collide when the name is the domain,
            // but a domain that folds to an existing slug would quietly file
            // two customers together, and that is not a thing to find out
            // from a client's report.
            if (taken.TryGetValue(slug, out var owner) && !owner.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine($"  {domain}: '{slug}' is already '{owner}'. Skipped; file it by hand.");
                continue;
            }

            taken[slug] = name;
            planned.Add((domain, name, slug));
            Console.WriteLine($"  {domain,-26} {name,-26} {slug,-24}");
        }

        Console.WriteLine();

        if (!apply) { return (planned.Count, 0); }

        var filed = 0;
        foreach (var (domain, name, slug) in planned)
        {
            ct.ThrowIfCancellationRequested();

            // Null means the slug already exists, which is what happens when
            // two domains map to one client. That is the intended outcome, not
            // a failure, so the assign below runs either way.
            await store.CreateClientAsync(name, slug, organization.Slug, ct).ConfigureAwait(false);

            // Scoped to this organization, so the client resolved is this
            // organization's and the domain cannot leave it.
            var outcome = await store.AssignDomainAsync(domain, slug, organization.Id, ct).ConfigureAwait(false);
            if (outcome is ReportStore.AssignOutcome.Assigned or ReportStore.AssignOutcome.AlreadyAssigned)
            {
                filed++;
            }
            else
            {
                Console.Error.WriteLine($"  {domain}: {outcome}");
            }
        }

        return (planned.Count, filed);
    }

    private static async Task<int> AssignAsync(ReportStore store, string dbPath, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        var client = Args.Value(args, "--client");

        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(client))
        {
            return Usage("dmarc client assign --domain <domain> --client <slug> [--db <path>]");
        }

        // --org scopes the assignment, as it scopes erase. Without it the
        // client slug ranged over every organization with LIMIT 1, so with
        // an "acme-corp" in two of them a domain and its history went to
        // whichever row SQLite returned first. Left out, the command still
        // works the way the master account does - across organizations.
        string? tenantId = null;
        var org = Args.Value(args, "--org");
        if (!string.IsNullOrWhiteSpace(org))
        {
            tenantId = await new ClientErasure(dbPath).OrganizationIdAsync(org, ct).ConfigureAwait(false);
            if (tenantId is null)
            {
                Console.Error.WriteLine($"No organization called '{org}'. Run: dmarc org list");
                return 66;
            }
        }

        var outcome = await store.AssignDomainAsync(domain, client, tenantId, ct).ConfigureAwait(false);
        switch (outcome)
        {
            case ReportStore.AssignOutcome.Assigned:
                Console.WriteLine($"{domain} is now filed under '{client}', along with everything already stored for it.");
                return 0;

            case ReportStore.AssignOutcome.AlreadyAssigned:
                Console.WriteLine($"{domain} was already filed under '{client}'. Nothing to do.");
                return 0;

            case ReportStore.AssignOutcome.DomainNotFound:
                // Naming a domain that is not there is nearly always a typo,
                // and the list of what IS there is the fastest way to see it.
                Console.Error.WriteLine($"No reports have been stored for '{domain}'.");
                var unassigned = await store.GetUnassignedDomainsAsync(ct: ct).ConfigureAwait(false);
                if (unassigned.Count > 0)
                {
                    Console.Error.WriteLine("Unassigned domains:");
                    foreach (var d in unassigned) { Console.Error.WriteLine($"    {d}"); }
                }
                return 66;

            default:
                Console.Error.WriteLine($"No client with the slug '{client}'.");
                var clients = await store.GetClientsAsync(ct: ct).ConfigureAwait(false);
                Console.Error.WriteLine("Clients:");
                foreach (var c in clients) { Console.Error.WriteLine($"    {c.Slug}"); }
                Console.Error.WriteLine();
                Console.Error.WriteLine($"  dmarc client add --name \"<name>\"");
                return 66;
        }
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine();
        Console.Error.WriteLine("  dmarc client list");
        Console.Error.WriteLine("  dmarc client add    --name \"<name>\" [--slug <slug>] [--org <organization slug>]");
        Console.Error.WriteLine("  dmarc client assign --domain <domain> --client <slug>");
        Console.Error.WriteLine("  dmarc client set-group --client <slug> --group <entra group object id>   (the customer's own login)");
        Console.Error.WriteLine("  dmarc client erase --client <slug> [--apply --confirm <slug> --by <name>]   (permanent)");
        return 64;
    }

    /// <summary>
    /// Removes a client and everything belonging to them, permanently.
    /// </summary>
    /// <remarks>
    /// The answer to "can we have our data deleted". Before this, the honest
    /// reply was that a domain could be hidden and the reports would age out in
    /// four hundred days - which is not an answer a paying customer accepts,
    /// and not one a customer of an MSP should get either.
    ///
    /// Guarded harder than anything else here, because it is the only
    /// operation in the product that cannot be undone from inside it. A dry
    /// run by default, like prune and fix; and --apply alone is not enough,
    /// because --apply is muscle memory by the time somebody reaches this. The
    /// slug has to be typed again into --confirm, which is the one thing a
    /// half-attentive paste of yesterday's command will not carry.
    /// </remarks>
    private static async Task<int> EraseAsync(string dbPath, string[] args, CancellationToken ct)
    {
        var client = Args.Value(args, "--client");
        if (string.IsNullOrWhiteSpace(client))
        {
            Console.Error.WriteLine("dmarc client erase --client <slug>                       what would go");
            Console.Error.WriteLine("dmarc client erase --client <slug> --apply --confirm <slug> --by <name>");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Permanent, and not undoable from here. Backups still hold a copy");
            Console.Error.WriteLine("  until they age out - the preview says until when.");
            return 64;
        }

        var erasure = new ClientErasure(dbPath);

        // --org is RESOLVED and passed, not ignored.
        //
        // This read "organization-wide on the command line, which is what an
        // operator standing at the machine has" and passed null. Client slugs
        // are unique per organization - UNIQUE(tenant_id, slug) - so two
        // organizations may each have an 'acme-corp', and null meant the
        // lookup ranged over both and took whichever SQLite returned first.
        //
        // Reproduced before it was fixed: `--org nextlayersec` printed NRG's
        // client and NRG's domain, said "in nrg", and would have permanently
        // destroyed the wrong customer's data on --apply. The tests missed it
        // because they exercised the service with an explicit tenant and never
        // this command.
        string? tenantId = null;
        var org = Args.Value(args, "--org");

        if (!string.IsNullOrWhiteSpace(org))
        {
            tenantId = await erasure.OrganizationIdAsync(org, ct).ConfigureAwait(false);

            if (tenantId is null)
            {
                Console.Error.WriteLine($"No organization called '{org}'. Run: dmarc org list");
                return 66;
            }
        }

        ErasureResult? preview;
        try
        {
            preview = await erasure.PreviewAsync(client, tenantId, ct).ConfigureAwait(false);
        }
        catch (AmbiguousClientException ex)
        {
            // Two organizations, one slug, no --org. There is no safe choice
            // to make here, and making one is exactly what went wrong.
            Console.Error.WriteLine($"  {ex.Message}");
            return 64;
        }

        if (preview is null)
        {
            Console.Error.WriteLine(
                org is null
                    ? $"No client called '{client}'. Run: dmarc client list"
                    : $"No client called '{client}' in {org}. Run: dmarc client list");
            return 66;
        }

        Console.WriteLine();
        Console.WriteLine($"  {preview.Describe()}");
        Console.WriteLine();

        foreach (var domain in preview.Domains) { Console.WriteLine($"    {domain}"); }
        if (preview.Domains.Count > 0) { Console.WriteLine(); }

        foreach (var (table, rows) in preview.Rows)
        {
            Console.WriteLine($"    {table,-28} {rows,10:N0}");
        }

        Console.WriteLine();

        if (!Args.Flag(args, "--apply"))
        {
            Console.WriteLine("  Nothing was removed. To do it:");
            Console.WriteLine($"    dmarc client erase --client {preview.Slug}{(org is null ? "" : $" --org {org}")} --apply --confirm {preview.Slug} --by <name>");
            Console.WriteLine();
            return 0;
        }

        // --apply is muscle memory by the time anybody reaches this command.
        // Typing the slug again is not.
        var confirmed = Args.Value(args, "--confirm");
        if (!string.Equals(confirmed, preview.Slug, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"  Refusing. Add --confirm {preview.Slug} to erase this client.");
            Console.Error.WriteLine("  Nothing was removed.");
            return 64;
        }

        var by = Args.Value(args, "--by");
        if (string.IsNullOrWhiteSpace(by))
        {
            Console.Error.WriteLine("  Refusing. --by <name> says who asked for this; it goes in the audit log.");
            Console.Error.WriteLine("  Nothing was removed.");
            return 64;
        }

        var result = await erasure
            .ApplyAsync(preview.Slug, tenantId, by, new AuditLog(dbPath), ct)
            .ConfigureAwait(false);

        Console.WriteLine($"  Erased. {result!.Total:N0} row(s) removed, and verified gone.");
        Console.WriteLine("  Recorded in the audit log.");
        Console.WriteLine();

        // Said every time, because somebody is about to tell a customer their
        // data is gone and it is not gone from the copies yet.
        Console.WriteLine("  Backups still hold this data. A nightly backup kept for 14 days means the");
        Console.WriteLine($"  last copy ages out around {DateTimeOffset.UtcNow.AddDays(14):yyyy-MM-dd}, and any offsite");
        Console.WriteLine("  sync carries its own retention. Say that timeframe rather than \"it is gone\".");
        Console.WriteLine();

        return 0;
    }
}
