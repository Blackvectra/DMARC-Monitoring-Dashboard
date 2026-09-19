using DmarcMonitor.Core.Storage;

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
        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        // The organisation new clients belong to. Everything else here names
        // a client or a domain by slug, which is unique across organisations.
        var store = new ReportStore(dbPath, Args.Value(rest, "--org") ?? ReportStore.DefaultTenantSlug);
        if (!await store.IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        return action switch
        {
            "list" => await ListAsync(store, ct).ConfigureAwait(false),
            "add" => await AddAsync(store, rest, ct).ConfigureAwait(false),
            "assign" => await AssignAsync(store, rest, ct).ConfigureAwait(false),
            "auto-assign" => await AutoAssignAsync(store, rest, ct).ConfigureAwait(false),
            "set-group" => await SetGroupAsync(store, rest, ct).ConfigureAwait(false),
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

        // The organisation column only earns its width once there are two.
        var organisations = clients.Select(c => c.OrganisationSlug).Distinct(StringComparer.Ordinal).Count() > 1;

        Console.WriteLine();
        Console.WriteLine($"  {"slug",-28} {"name",-32} {"domains",7} {"messages",9}{(organisations ? "  organisation" : "")}");
        foreach (var c in clients)
        {
            Console.WriteLine($"  {c.Slug,-28} {c.Name,-32} {c.Domains,7} {c.Messages,9:N0}{(organisations ? "  " + c.OrganisationSlug : "")}");
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
            return Usage("dmarc client add --name \"<name>\" [--slug <slug>] [--org <organisation slug>] [--db <path>]");
        }

        var slug = await store.CreateClientAsync(name, Args.Value(args, "--slug"), store.Organisation, ct).ConfigureAwait(false);
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
    private static async Task<int> AutoAssignAsync(ReportStore store, string[] args, CancellationToken ct)
    {
        var apply = Args.Flag(args, "--apply");

        var domains = await store.GetUnassignedDomainsAsync(ct: ct).ConfigureAwait(false);
        if (domains.Count == 0)
        {
            Console.WriteLine("Every domain is already filed under a client.");
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"  {"domain",-26} {"client",-26} {"slug",-24}");

        var taken = (await store.GetClientsAsync(ct: ct).ConfigureAwait(false))
            .ToDictionary(c => c.Slug, c => c.Name, StringComparer.OrdinalIgnoreCase);

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

        if (!apply)
        {
            Console.WriteLine($"  {planned.Count} domain(s) would be filed. Nothing has been written.");
            Console.WriteLine("  The slug goes into report filenames and cannot be changed afterwards.");
            Console.WriteLine("  Run it for real:  dmarc client auto-assign --apply");
            Console.WriteLine();
            return 0;
        }

        var filed = 0;
        foreach (var (domain, name, slug) in planned)
        {
            ct.ThrowIfCancellationRequested();

            // Null means the slug already exists, which is what happens when
            // two domains map to one client. That is the intended outcome, not
            // a failure, so the assign below runs either way.
            await store.CreateClientAsync(name, slug, ct: ct).ConfigureAwait(false);

            var outcome = await store.AssignDomainAsync(domain, slug, ct: ct).ConfigureAwait(false);
            if (outcome is ReportStore.AssignOutcome.Assigned or ReportStore.AssignOutcome.AlreadyAssigned)
            {
                filed++;
            }
            else
            {
                Console.Error.WriteLine($"  {domain}: {outcome}");
            }
        }

        Console.WriteLine($"  {filed} domain(s) filed.");
        Console.WriteLine("  Check it: dmarc client list");
        Console.WriteLine();
        return filed == planned.Count ? 0 : 65;
    }

    private static async Task<int> AssignAsync(ReportStore store, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        var client = Args.Value(args, "--client");

        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(client))
        {
            return Usage("dmarc client assign --domain <domain> --client <slug> [--db <path>]");
        }

        var outcome = await store.AssignDomainAsync(domain, client, ct: ct).ConfigureAwait(false);
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
        Console.Error.WriteLine("  dmarc client add    --name \"<name>\" [--slug <slug>] [--org <organisation slug>]");
        Console.Error.WriteLine("  dmarc client assign --domain <domain> --client <slug>");
        Console.Error.WriteLine("  dmarc client set-group --client <slug> --group <entra group object id>   (the customer's own login)");
        return 64;
    }
}
