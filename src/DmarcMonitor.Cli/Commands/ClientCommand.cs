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

        var store = new ReportStore(dbPath);
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
            _ => Usage($"Unknown: dmarc client {action}"),
        };
    }

    private static async Task<int> ListAsync(ReportStore store, CancellationToken ct)
    {
        var clients = await store.GetClientsAsync(ct).ConfigureAwait(false);
        if (clients.Count == 0)
        {
            Console.WriteLine("No clients yet. Import some reports first, then: dmarc client add --name \"<name>\"");
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"  {"slug",-28} {"name",-32} {"domains",7} {"messages",9}");
        foreach (var c in clients)
        {
            Console.WriteLine($"  {c.Slug,-28} {c.Name,-32} {c.Domains,7} {c.Messages,9:N0}");
        }

        var unassigned = await store.GetUnassignedDomainsAsync(ct).ConfigureAwait(false);
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
            return Usage("dmarc client add --name \"<name>\" [--slug <slug>] [--db <path>]");
        }

        var slug = await store.CreateClientAsync(name, Args.Value(args, "--slug"), ct).ConfigureAwait(false);
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

    private static async Task<int> AssignAsync(ReportStore store, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        var client = Args.Value(args, "--client");

        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(client))
        {
            return Usage("dmarc client assign --domain <domain> --client <slug> [--db <path>]");
        }

        var outcome = await store.AssignDomainAsync(domain, client, ct).ConfigureAwait(false);
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
                var unassigned = await store.GetUnassignedDomainsAsync(ct).ConfigureAwait(false);
                if (unassigned.Count > 0)
                {
                    Console.Error.WriteLine("Unassigned domains:");
                    foreach (var d in unassigned) { Console.Error.WriteLine($"    {d}"); }
                }
                return 66;

            default:
                Console.Error.WriteLine($"No client with the slug '{client}'.");
                var clients = await store.GetClientsAsync(ct).ConfigureAwait(false);
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
        Console.Error.WriteLine("  dmarc client add    --name \"<name>\" [--slug <slug>]");
        Console.Error.WriteLine("  dmarc client assign --domain <domain> --client <slug>");
        return 64;
    }
}
