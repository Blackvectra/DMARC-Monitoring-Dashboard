using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Organizations: the layer above clients, and which Entra group belongs to
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
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        // --colour is still accepted. The product says color everywhere now,
        // and refusing the other spelling would only punish somebody who
        // copied a command out of an older page.
        if (Args.Reject(args, "--db", "--org", "--name", "--slug", "--group", "--role", "--color", "--colour", "--provider-name", "--contact", "--logo", "!--clear") is var bad and not 0) { return bad; }

        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        if (!await new ReportStore(dbPath).IsInitializedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        var store = new OrganizationStore(dbPath);
        return action switch
        {
            "list" => await ListAsync(store, ct).ConfigureAwait(false),
            "add" => await AddAsync(store, rest, ct).ConfigureAwait(false),
            "set-group" => await SetGroupAsync(store, rest, ct).ConfigureAwait(false),
            "rename" => await RenameAsync(store, rest, ct).ConfigureAwait(false),
            "brand" => await BrandAsync(store, rest, ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc org {action}"),
        };
    }

    /// <summary>
    /// How the organization looks: the accent color and logo in the sidebar,
    /// and how it names itself on the reports it sends.
    /// </summary>
    private static async Task<int> BrandAsync(OrganizationStore store, string[] args, CancellationToken ct)
    {
        var slug = Args.Value(args, "--org");
        if (string.IsNullOrWhiteSpace(slug))
        {
            return Usage("dmarc org brand --org <slug> [--color #rrggbb] [--provider-name <n>] [--contact <text>] [--logo <image file>] [--clear] [--db <path>]");
        }

        var existing = await store.GetAsync(slug, ct).ConfigureAwait(false);
        if (existing is null)
        {
            Console.Error.WriteLine($"No organization with the slug '{slug}'. See: dmarc org list");
            return 66;
        }

        var brand = Args.Flag(args, "--clear") ? OrganizationBrand.None : existing.Brand;
        if ((Args.Value(args, "--color") ?? Args.Value(args, "--colour")) is { } color)
        {
            brand = brand with { PrimaryColor = color };
        }
        if (Args.Value(args, "--provider-name") is { } provider) { brand = brand with { ProviderName = provider }; }
        if (Args.Value(args, "--contact") is { } contact) { brand = brand with { ContactBlock = contact.Replace("\\n", "\n", StringComparison.Ordinal) }; }
        if (Args.Value(args, "--logo") is { } logoPath)
        {
            if (!File.Exists(logoPath))
            {
                Console.Error.WriteLine($"No such file: {logoPath}");
                return 66;
            }
            var type = Path.GetExtension(logoPath).ToLowerInvariant() switch
            {
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".webp" => "image/webp",
                ".svg" => "image/svg+xml",
                _ => null,
            };
            if (type is null)
            {
                Console.Error.WriteLine("The logo has to be a .png, .jpg, .gif, .webp or .svg file.");
                return 65;
            }
            brand = brand with { Logo = $"data:{type};base64,{Convert.ToBase64String(await File.ReadAllBytesAsync(logoPath, ct).ConfigureAwait(false))}" };
        }

        try
        {
            await store.SetBrandAsync(slug, brand, ct).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }

        Console.WriteLine($"'{slug}' now looks like this:");
        Console.WriteLine($"  color        {brand.PrimaryColor ?? "(default)"}");
        Console.WriteLine($"  logo          {(brand.Logo is null ? "(none)" : $"{brand.Logo.Length / 1000} KB")}");
        Console.WriteLine($"  provider name {brand.ProviderName ?? "(from configuration)"}");
        Console.WriteLine($"  contact       {(brand.ContactBlock is null ? "(none)" : brand.ContactBlock.Replace("\n", " / ", StringComparison.Ordinal))}");
        return 0;
    }

    private static async Task<int> ListAsync(OrganizationStore store, CancellationToken ct)
    {
        var all = await store.ListAsync(ct).ConfigureAwait(false);
        if (all.Count == 0)
        {
            Console.WriteLine("No organizations yet. The first is created by the first report or client; or: dmarc org add --name \"<name>\"");
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

    private static async Task<int> AddAsync(OrganizationStore store, string[] args, CancellationToken ct)
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
                : $"An organization with the slug '{wanted}' already exists.");
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

    private static async Task<int> SetGroupAsync(OrganizationStore store, string[] args, CancellationToken ct)
    {
        var slug = Args.Value(args, "--org");
        if (string.IsNullOrWhiteSpace(slug))
        {
            return Usage("dmarc org set-group --org <slug> --group <entra group object id> [--role operator|admin|viewer] [--db <path>]   (omit --group to clear it)");
        }

        var role = (Args.Value(args, "--role") ?? "operator").ToLowerInvariant() switch
        {
            "operator" => OrganizationRole.Operator,
            "admin" => OrganizationRole.Admin,
            "viewer" => OrganizationRole.Viewer,
            var other => throw new ArgumentException($"--role {other}: one of operator, admin, viewer."),
        };

        var group = Args.Value(args, "--group");
        if (!await store.SetGroupAsync(slug, role, group, ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"No organization with the slug '{slug}'. See: dmarc org list");
            return 66;
        }

        var roleName = role.ToString().ToLowerInvariant();
        Console.WriteLine(string.IsNullOrWhiteSpace(group)
            ? $"'{slug}' has no {roleName} group now."
            : $"Members of {group.Trim()} are {roleName}s of '{slug}'. Anybody already signed in sees it after signing out and back in.");
        return 0;
    }

    private static async Task<int> RenameAsync(OrganizationStore store, string[] args, CancellationToken ct)
    {
        var slug = Args.Value(args, "--org");
        var name = Args.Value(args, "--name");
        if (string.IsNullOrWhiteSpace(slug) || string.IsNullOrWhiteSpace(name))
        {
            return Usage("dmarc org rename --org <slug> --name \"<name>\" [--db <path>]");
        }

        if (!await store.RenameAsync(slug, name, ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"No organization with the slug '{slug}'. See: dmarc org list");
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
        Console.Error.WriteLine("  dmarc org set-group --org <slug> --group <entra group object id> [--role operator|admin|viewer]");
        Console.Error.WriteLine("  dmarc org rename    --org <slug> --name \"<name>\"");
        Console.Error.WriteLine("  dmarc org brand     --org <slug> [--color #rrggbb] [--provider-name <n>] [--contact <text>] [--logo <file>]");
        return 64;
    }
}
