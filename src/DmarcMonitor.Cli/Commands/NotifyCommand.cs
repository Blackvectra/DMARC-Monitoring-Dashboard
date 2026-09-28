using System.Globalization;
using DmarcMonitor.Core.Notifications;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Where an organization's findings are sent, and sending them.
///
/// Two kinds of destination: a webhook, given a signed POST per change, and
/// a ConnectWise PSA, given a ticket per finding (docs/CONNECTWISE.md).
///
/// No secret goes on the command line - the webhook's signing key or the
/// ConnectWise private key - for the same reasons as a DNS credential: shell
/// history, process listings, the screenshot on the ticket. Each is read from
/// an environment variable, from stdin, or typed at a prompt that does not
/// echo. The webhook address is treated the same way once stored, because
/// for most chat tools the address is the credential.
/// </summary>
public static class NotifyCommand
{
    private const string SecretVariable = "DMARC_WEBHOOK_SECRET";
    private const string PrivateKeyVariable = "DMARC_CONNECTWISE_PRIVATE_KEY";

    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--org", "--url", "--min-severity", "--link-base", "--secrets", "--kind",
                "--site", "--company-id", "--client-id", "--public-key", "--board", "--status",
                "--priority-critical", "--priority-warning", "--search", "--client", "!--secret-stdin") is var bad and not 0)
        {
            return bad;
        }

        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        if (!await new ReportStore(dbPath).IsInitializedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        if (!await SchemaGuard.IsCurrentAsync(dbPath, ct).ConfigureAwait(false)) { return 69; }

        // The same folder the web app is configured with, on a server; the
        // account's own folder otherwise. A run given a different one from the
        // run that set the destination finds no key, and says so.
        var secretsDir = Args.Value(rest, "--secrets");
        var secrets = new LocalSecretStore(string.IsNullOrWhiteSpace(secretsDir) ? null : Path.GetFullPath(secretsDir));
        var org = Args.Value(rest, "--org") ?? ReportStore.DefaultTenantSlug;

        string? kind;
        try
        {
            kind = Args.Value(rest, "--kind") is { } given ? WebhookStore.ParseKind(given) : null;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 64;
        }

        return action switch
        {
            "list" => await ListAsync(new WebhookStore(dbPath, secrets), ct).ConfigureAwait(false),
            "set" when kind == WebhookStore.ConnectWiseKind => await SetConnectWiseAsync(new WebhookStore(dbPath, secrets), org, rest, ct).ConfigureAwait(false),
            "set" => await SetAsync(new WebhookStore(dbPath, secrets), org, rest, ct).ConfigureAwait(false),
            "remove" => await RemoveAsync(new WebhookStore(dbPath, secrets), org, kind ?? WebhookStore.WebhookKind, ct).ConfigureAwait(false),
            "test" => await TestAsync(new WebhookStore(dbPath, secrets), new WebhookNotifier(dbPath, secrets), org, kind, Args.Value(rest, "--client"), ct).ConfigureAwait(false),
            "send" => await SendAsync(new WebhookNotifier(dbPath, secrets), Args.Value(rest, "--org"), ct).ConfigureAwait(false),
            "companies" => await CompaniesAsync(new WebhookNotifier(dbPath, secrets), org, Args.Value(rest, "--search"), ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc notify {action}"),
        };
    }

    private static async Task<int> ListAsync(WebhookStore store, CancellationToken ct)
    {
        Console.WriteLine();
        Console.WriteLine($"  Secrets: {store.Secrets.Description}");
        Console.WriteLine();

        var all = await store.ListAsync(ct).ConfigureAwait(false);
        if (all.Count == 0)
        {
            Console.WriteLine("  No destinations. What this finds is seen only by opening it.");
            Console.WriteLine("  dmarc notify set --org <slug> --url https://...");
            Console.WriteLine("  dmarc notify set --org <slug> --kind connectwise --site https://... --board <name> ...");
            return 0;
        }

        foreach (var hook in all)
        {
            var where = hook.IsConnectWise
                ? $"ConnectWise {hook.Destination}, board '{hook.ConnectWise?.Board}'"
                : hook.Destination;
            Console.WriteLine($"  {hook.TenantSlug,-20} {where}  ({hook.MinSeverity} and above)");
            Console.WriteLine($"  {"",-20} set {Show(hook.CreatedAt)} by {hook.CreatedBy}");
            Console.WriteLine($"  {"",-20} last delivered {(hook.LastDeliveredAt is { } at ? Show(at) : "never")}");
            if (hook.IsFailing) { Console.WriteLine($"  {"",-20} FAILING since {Show(hook.LastErrorAt!.Value)}: {hook.LastError}"); }
        }
        Console.WriteLine();
        return 0;
    }

    private static async Task<int> SetAsync(WebhookStore store, string org, string[] args, CancellationToken ct)
    {
        var url = Args.Value(args, "--url");
        if (string.IsNullOrWhiteSpace(url))
        {
            return Usage("dmarc notify set [--org <slug>] --url https://... [--min-severity warning] [--link-base https://dmarc.example.com]");
        }

        var secret = await ReadSecretAsync(args, SecretVariable, "Signing secret (the receiver is given the same one): ", ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(secret))
        {
            Console.Error.WriteLine($"No signing secret given. Set {SecretVariable}, pipe it with --secret-stdin, or run interactively to be prompted.");
            Console.Error.WriteLine("The receiver needs the same one. Generate it with: openssl rand -hex 32");
            return 64;
        }

        try
        {
            var hook = await store.SetAsync(org, url, secret,
                Args.Value(args, "--min-severity") ?? "warning", Args.Value(args, "--link-base"),
                Actor(), ct).ConfigureAwait(false);

            Console.WriteLine($"{hook.TenantSlug}: {hook.MinSeverity} and above now goes to {hook.Destination}.");
            Console.WriteLine($"Address and signing key stored as {hook.CredentialRef}. {store.Secrets.Description}");
            Console.WriteLine("Changes detected from now on are sent; earlier ones are not.");
            Console.WriteLine($"Prove the receiver works: dmarc notify test --org {hook.TenantSlug}");
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    /// <summary>
    /// The ConnectWise credential is four parts, and three of them go on the
    /// command line: the site, the company id and the public key are not
    /// secrets on their own (the public key is the API member's username, in
    /// effect). The private key is, and is read like the signing secret.
    /// </summary>
    private static async Task<int> SetConnectWiseAsync(WebhookStore store, string org, string[] args, CancellationToken ct)
    {
        var site = Args.Value(args, "--site");
        var companyId = Args.Value(args, "--company-id");
        var clientId = Args.Value(args, "--client-id");
        var publicKey = Args.Value(args, "--public-key");
        var board = Args.Value(args, "--board");

        if (string.IsNullOrWhiteSpace(site) || string.IsNullOrWhiteSpace(companyId) || string.IsNullOrWhiteSpace(clientId)
            || string.IsNullOrWhiteSpace(publicKey) || string.IsNullOrWhiteSpace(board))
        {
            return Usage("dmarc notify set --kind connectwise [--org <slug>] --site https://api-na.myconnectwise.net --company-id <id> "
                         + "--client-id <guid> --public-key <key> --board <name> [--status <name>] "
                         + "[--priority-critical <name>] [--priority-warning <name>] [--min-severity warning] [--link-base https://...]");
        }

        var privateKey = await ReadSecretAsync(args, PrivateKeyVariable, "ConnectWise private key (from the API member's key pair): ", ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(privateKey))
        {
            Console.Error.WriteLine($"No private key given. Set {PrivateKeyVariable}, pipe it with --secret-stdin, or run interactively to be prompted.");
            return 64;
        }

        try
        {
            var settings = new ConnectWiseSettings(board, Args.Value(args, "--status"),
                Args.Value(args, "--priority-critical"), Args.Value(args, "--priority-warning"));

            var hook = await store.SetConnectWiseAsync(org, site, companyId, publicKey, privateKey, clientId, settings,
                Args.Value(args, "--min-severity") ?? "warning", Args.Value(args, "--link-base"), Actor(), ct).ConfigureAwait(false);

            Console.WriteLine($"{hook.TenantSlug}: {hook.MinSeverity} and above now becomes tickets on '{settings.Board}' at {hook.Destination}.");
            Console.WriteLine($"Keys stored as {hook.CredentialRef}. {store.Secrets.Description}");
            Console.WriteLine("Changes detected from now on are filed; earlier ones are not.");
            Console.WriteLine();
            Console.WriteLine("Each client is filed on its own ConnectWise company, which is never guessed from a name:");
            Console.WriteLine($"  dmarc notify companies --org {hook.TenantSlug} --search \"Acme\"");
            Console.WriteLine("  dmarc client set-connectwise --client <slug> --company <id>");
            Console.WriteLine($"Prove it: dmarc notify test --org {hook.TenantSlug} --kind connectwise [--client <slug>]");
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    private static async Task<int> RemoveAsync(WebhookStore store, string org, string kind, CancellationToken ct)
    {
        var removed = await store.RemoveAsync(org, Actor(), kind, ct).ConfigureAwait(false);
        Console.WriteLine(removed
            ? $"Removed the {kind} destination, with its address and keys. Nothing more will be sent there."
            : $"'{org}' has no {kind} destination to remove.");
        return 0;
    }

    /// <summary>
    /// Every destination the organization has, or the one kind asked for.
    /// A webhook gets a signed ping; ConnectWise gets a sign-in, a look for
    /// the board, and with --client a test ticket on that client's company.
    /// </summary>
    private static async Task<int> TestAsync(
        WebhookStore store, WebhookNotifier notifier, string org, string? kind, string? client, CancellationToken ct)
    {
        var kinds = kind is not null
            ? [kind]
            : (await store.ForOrganizationAsync(org, ct).ConfigureAwait(false)).Select(h => h.Kind).ToList();

        if (kinds.Count == 0)
        {
            Console.Error.WriteLine($"'{org}' has no destination. Set one with: dmarc notify set --org {org} ...");
            return 65;
        }

        var failed = 0;
        foreach (var each in kinds)
        {
            try
            {
                if (each == WebhookStore.ConnectWiseKind)
                {
                    var check = await notifier.TestConnectWiseAsync(org, client, ct).ConfigureAwait(false);
                    (check.Worked ? Console.Out : Console.Error).WriteLine(check.Message);
                    if (!check.Worked) { failed++; }
                    continue;
                }

                var run = await notifier.PingAsync(org, ct).ConfigureAwait(false);
                if (run.Worked)
                {
                    Console.WriteLine($"{run.Destination} accepted a signed test event.");
                }
                else
                {
                    Console.Error.WriteLine($"{run.Destination} did not accept it: {run.Error}");
                    failed++;
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine(ex.Message);
                failed++;
            }
        }

        return failed == 0 ? 0 : 1;
    }

    /// <summary>
    /// What the notify unit runs after each DNS scan. No destinations is an
    /// ordinary answer, not a failure: every install runs this, and most have
    /// not set one up.
    /// </summary>
    private static async Task<int> SendAsync(WebhookNotifier notifier, string? org, CancellationToken ct)
    {
        var runs = await notifier.SendAsync(org, ct).ConfigureAwait(false);
        if (runs.Count == 0)
        {
            Console.WriteLine(org is null ? "No destinations configured; nothing to send." : $"'{org}' has no destination.");
            return 0;
        }

        foreach (var run in runs)
        {
            var line = $"{run.TenantSlug}: {run.Delivered} sent to {run.Destination}";
            if (run.Waiting > 0) { line += $", {run.Waiting} waiting"; }
            Console.WriteLine(line + ".");
            if (run.Error is not null) { Console.Error.WriteLine($"{run.TenantSlug}: stopped: {run.Error}"); }

            // Not a failure of the destination, and not silent either: a
            // client nobody has mapped is a finding nobody will see.
            if (run.Unmapped.Count > 0)
            {
                Console.Error.WriteLine($"{run.TenantSlug}: waiting for a ConnectWise company on: {string.Join(", ", run.Unmapped)}");
                Console.Error.WriteLine("  Set it with: dmarc client set-connectwise --client <slug> --company <id>  (dmarc notify companies --search finds the id)");
            }
        }

        // A run that could not deliver is a failed run: the unit goes red,
        // and dmarc health says so too, rather than the findings quietly
        // piling up somewhere nobody is reading.
        return runs.All(r => r.Worked) ? 0 : 1;
    }

    private static async Task<int> CompaniesAsync(WebhookNotifier notifier, string org, string? search, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(search))
        {
            return Usage("dmarc notify companies [--org <slug>] --search <part of the company's name or identifier>");
        }

        try
        {
            var found = await notifier.SearchCompaniesAsync(org, search, ct).ConfigureAwait(false);
            if (found.Count == 0)
            {
                Console.WriteLine($"No ConnectWise company has '{search}' in its name or identifier.");
                return 0;
            }

            Console.WriteLine();
            Console.WriteLine($"  {"id",8}  {"identifier",-20} name");
            foreach (var company in found)
            {
                Console.WriteLine($"  {company.Id,8}  {company.Identifier,-20} {company.Name}");
            }
            Console.WriteLine();
            Console.WriteLine("  Then: dmarc client set-connectwise --client <slug> --company <id>");
            return 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ConnectWiseException)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    private static async Task<string?> ReadSecretAsync(string[] args, string variable, string prompt, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(variable) is { Length: > 0 } fromEnv) { return fromEnv; }

        if (Args.Flag(args, "--secret-stdin"))
        {
            var line = await Console.In.ReadLineAsync(ct).ConfigureAwait(false);
            return line?.Trim();
        }

        if (Console.IsInputRedirected) { return null; }

        Console.Write(prompt);
        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace) { if (chars.Count > 0) { chars.RemoveAt(chars.Count - 1); } continue; }
            if (!char.IsControl(key.KeyChar)) { chars.Add(key.KeyChar); }
        }
        return new string([.. chars]).Trim();
    }

    private static string Actor() => $"{Environment.UserName} (command line)";

    private static string Show(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);

    private static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("""

              dmarc notify list
              dmarc notify set [--org <slug>] --url https://... [--min-severity info|warning|critical]
                               [--link-base https://dmarc.example.com]
              dmarc notify set [--org <slug>] --kind connectwise --site https://api-na.myconnectwise.net
                               --company-id <id> --client-id <guid> --public-key <key> --board <name>
                               [--status <name>] [--priority-critical <name>] [--priority-warning <name>]
                               [--min-severity warning] [--link-base https://...]
              dmarc notify companies [--org <slug>] --search <text>
              dmarc notify test [--org <slug>] [--kind webhook|connectwise] [--client <slug>]
              dmarc notify send [--org <slug>]
              dmarc notify remove [--org <slug>] [--kind webhook|connectwise]

              --secrets <dir>  The secret store folder; on a server, the one the web app uses.
              --db <path>      Database file. Default: dmarc.db

              The webhook's signing secret is read from DMARC_WEBHOOK_SECRET, and the
              ConnectWise private key from DMARC_CONNECTWISE_PRIVATE_KEY; either from stdin
              with --secret-stdin, or at a prompt. Never as an argument.
            """);
        return 64;
    }
}
