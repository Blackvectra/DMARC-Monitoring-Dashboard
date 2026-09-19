using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Organisations: the layer above clients, and which Entra group belongs to
/// each.
///
/// A fresh install has one, filed as 'local' and called Local until somebody
/// renames it. A second is what separates one company's clients from
/// another's: NRG Tech Services' people see NRG's clients, NextLayerSec's
/// people see NextLayerSec's, and the master group named in the web app's
/// configuration sees both.
/// </summary>
public static class OrgCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        if (!await new ReportStore(dbPath).IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        var store = new OrganisationStore(dbPath);
        return action switch
        {
            "list" => await ListAsync(store, ct).ConfigureAwait(false),
            "add" => await AddAsync(store, rest, ct).ConfigureAwait(false),
            "set-group" => await SetGroupAsync(store, rest, ct).ConfigureAwait(false),
            "rename" => await RenameAsync(store, rest, ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc org {action}"),
        };
    }

    private static async Task<int> ListAsync(OrganisationStore store, CancellationToken ct)
    {
        var all = await store.ListAsync(ct).ConfigureAwait(false);
        if (all.Count == 0)
        {
            Console.WriteLine("No organisations yet. The first is created by the first report or client; or: dmarc org add --name \"<name>\"");
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"  {"slug",-24} {"name",-28} {"clients",7} {"domains",7}  entra group");
        foreach (var o in all)
        {
            Console.WriteLine($"  {o.Slug,-24} {o.Name,-28} {o.Clients,7} {o.Domains,7}  {o.EntraGroupId ?? "(none: only the master group sees it)"}");
        }
        Console.WriteLine();
        return 0;
    }

    private static async Task<int> AddAsync(OrganisationStore store, string[] args, CancellationToken ct)
    {
        var name = Args.Value(args, "--name");
        if (string.IsNullOrWhiteSpace(name))
        {
            return Usage("dmarc org add --name \"<name>\" [--slug <slug>] [--group <entra group object id>] [--db <path>]");
        }

        var created = await store.CreateAsync(name, Args.Value(args, "--slug"), Args.Value(args, "--group"), ct).ConfigureAwait(false);
        if (created is null)
        {
            var wanted = ReportStore.Slugify(Args.Value(args, "--slug") ?? name);
            Console.Error.WriteLine(wanted.Length == 0
                ? $"'{name}' has no letters or digits to make a slug from. Pass --slug <slug>."
                : $"An organisation with the slug '{wanted}' already exists.");
            return 65;
        }

        Console.WriteLine($"Added {created.Name} as '{created.Slug}'.");
        if (created.EntraGroupId is null)
        {
            Console.WriteLine($"Nobody but the master group can see it yet. Next: dmarc org set-group --org {created.Slug} --group <entra group object id>");
        }
        Console.WriteLine($"Clients go in it with: dmarc client add --name \"<name>\" --org {created.Slug}");
        Console.WriteLine($"A collector for its mailbox files new domains there with: dmarc ingest ... --org {created.Slug}");
        return 0;
    }

    private static async Task<int> SetGroupAsync(OrganisationStore store, string[] args, CancellationToken ct)
    {
        var slug = Args.Value(args, "--org");
        if (string.IsNullOrWhiteSpace(slug))
        {
            return Usage("dmarc org set-group --org <slug> --group <entra group object id> [--db <path>]   (omit --group to clear it)");
        }

        var group = Args.Value(args, "--group");
        if (!await store.SetGroupAsync(slug, group, ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"No organisation with the slug '{slug}'. See: dmarc org list");
            return 66;
        }

        Console.WriteLine(string.IsNullOrWhiteSpace(group)
            ? $"'{slug}' has no group now; only the master group sees it."
            : $"Members of {group.Trim()} now see '{slug}'. Anybody already signed in sees it after signing out and back in.");
        return 0;
    }

    private static async Task<int> RenameAsync(OrganisationStore store, string[] args, CancellationToken ct)
    {
        var slug = Args.Value(args, "--org");
        var name = Args.Value(args, "--name");
        if (string.IsNullOrWhiteSpace(slug) || string.IsNullOrWhiteSpace(name))
        {
            return Usage("dmarc org rename --org <slug> --name \"<name>\" [--db <path>]");
        }

        if (!await store.RenameAsync(slug, name, ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"No organisation with the slug '{slug}'. See: dmarc org list");
            return 66;
        }

        Console.WriteLine($"'{slug}' is now called {name.Trim()}. The slug stays as it was.");
        return 0;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine();
        Console.Error.WriteLine("  dmarc org list");
        Console.Error.WriteLine("  dmarc org add       --name \"<name>\" [--slug <slug>] [--group <id>]");
        Console.Error.WriteLine("  dmarc org set-group --org <slug> --group <entra group object id>");
        Console.Error.WriteLine("  dmarc org rename    --org <slug> --name \"<name>\"");
        return 64;
    }
}
