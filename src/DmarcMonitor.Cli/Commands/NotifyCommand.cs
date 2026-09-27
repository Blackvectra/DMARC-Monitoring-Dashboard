using System.Globalization;
using DmarcMonitor.Core.Notifications;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Where an organization's findings are sent, and sending them.
///
/// The signing secret never goes on the command line, for the same reasons as
/// a DNS credential: shell history, process listings, the screenshot on the
/// ticket. It is read from DMARC_WEBHOOK_SECRET, from stdin, or typed at a
/// prompt that does not echo. The address is treated the same way once
/// stored, because for most chat tools the address is the credential.
/// </summary>
public static class NotifyCommand
{
    private const string SecretVariable = "DMARC_WEBHOOK_SECRET";

    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--org", "--url", "--min-severity", "--link-base", "--secrets", "!--secret-stdin") is var bad and not 0) { return bad; }

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
        // run that set the webhook finds no key, and says so.
        var secretsDir = Args.Value(rest, "--secrets");
        var secrets = new LocalSecretStore(string.IsNullOrWhiteSpace(secretsDir) ? null : Path.GetFullPath(secretsDir));
        var org = Args.Value(rest, "--org");

        return action switch
        {
            "list" => await ListAsync(new WebhookStore(dbPath, secrets), ct).ConfigureAwait(false),
            "set" => await SetAsync(new WebhookStore(dbPath, secrets), org, rest, ct).ConfigureAwait(false),
            "remove" => await RemoveAsync(new WebhookStore(dbPath, secrets), org, ct).ConfigureAwait(false),
            "test" => await TestAsync(new WebhookNotifier(dbPath, secrets), org, ct).ConfigureAwait(false),
            "send" => await SendAsync(new WebhookNotifier(dbPath, secrets), org, ct).ConfigureAwait(false),
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
            Console.WriteLine("  No webhooks. What this finds is seen only by opening it.");
            Console.WriteLine("  dmarc notify set --org <slug> --url https://...");
            return 0;
        }

        foreach (var hook in all)
        {
            Console.WriteLine($"  {hook.TenantSlug,-20} {hook.Destination}  ({hook.MinSeverity} and above)");
            Console.WriteLine($"  {"",-20} set {Show(hook.CreatedAt)} by {hook.CreatedBy}");
            Console.WriteLine($"  {"",-20} last delivered {(hook.LastDeliveredAt is { } at ? Show(at) : "never")}");
            if (hook.IsFailing) { Console.WriteLine($"  {"",-20} FAILING since {Show(hook.LastErrorAt!.Value)}: {hook.LastError}"); }
        }
        Console.WriteLine();
        return 0;
    }

    private static async Task<int> SetAsync(WebhookStore store, string? org, string[] args, CancellationToken ct)
    {
        var url = Args.Value(args, "--url");
        if (string.IsNullOrWhiteSpace(url))
        {
            return Usage("dmarc notify set [--org <slug>] --url https://... [--min-severity warning] [--link-base https://dmarc.example.com]");
        }

        var secret = await ReadSecretAsync(args, ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(secret))
        {
            Console.Error.WriteLine($"No signing secret given. Set {SecretVariable}, pipe it with --secret-stdin, or run interactively to be prompted.");
            Console.Error.WriteLine("The receiver needs the same one. Generate it with: openssl rand -hex 32");
            return 64;
        }

        try
        {
            var hook = await store.SetAsync(org ?? ReportStore.DefaultTenantSlug, url, secret,
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

    private static async Task<int> RemoveAsync(WebhookStore store, string? org, CancellationToken ct)
    {
        var removed = await store.RemoveAsync(org ?? ReportStore.DefaultTenantSlug, Actor(), ct).ConfigureAwait(false);
        Console.WriteLine(removed ? "Removed, with its address and key. Nothing more will be sent." : "There was no webhook to remove.");
        return 0;
    }

    private static async Task<int> TestAsync(WebhookNotifier notifier, string? org, CancellationToken ct)
    {
        try
        {
            var run = await notifier.PingAsync(org ?? ReportStore.DefaultTenantSlug, ct).ConfigureAwait(false);
            if (run.Worked)
            {
                Console.WriteLine($"{run.Destination} accepted a signed test event.");
                return 0;
            }

            Console.Error.WriteLine($"{run.Destination} did not accept it: {run.Error}");
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    /// <summary>
    /// What the notify unit runs after each DNS scan. No webhooks is an
    /// ordinary answer, not a failure: every install runs this, and most have
    /// not set one up.
    /// </summary>
    private static async Task<int> SendAsync(WebhookNotifier notifier, string? org, CancellationToken ct)
    {
        var runs = await notifier.SendAsync(org, ct).ConfigureAwait(false);
        if (runs.Count == 0)
        {
            Console.WriteLine(org is null ? "No webhooks configured; nothing to send." : $"'{org}' has no webhook.");
            return 0;
        }

        foreach (var run in runs)
        {
            var line = $"{run.TenantSlug}: {run.Delivered} sent to {run.Destination}";
            if (run.Waiting > 0) { line += $", {run.Waiting} waiting"; }
            Console.WriteLine(line + ".");
            if (run.Error is not null) { Console.Error.WriteLine($"{run.TenantSlug}: stopped: {run.Error}"); }
        }

        // A run that could not deliver is a failed run: the unit goes red,
        // and dmarc health says so too, rather than the findings quietly
        // piling up somewhere nobody is reading.
        return runs.All(r => r.Worked) ? 0 : 1;
    }

    private static async Task<string?> ReadSecretAsync(string[] args, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(SecretVariable) is { Length: > 0 } fromEnv) { return fromEnv; }

        if (Args.Flag(args, "--secret-stdin"))
        {
            var line = await Console.In.ReadLineAsync(ct).ConfigureAwait(false);
            return line?.Trim();
        }

        if (Console.IsInputRedirected) { return null; }

        Console.Write("Signing secret (the receiver is given the same one): ");
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
              dmarc notify test [--org <slug>]
              dmarc notify send [--org <slug>]
              dmarc notify remove [--org <slug>]

              --secrets <dir>  The secret store folder; on a server, the one the web app uses.
              --db <path>      Database file. Default: dmarc.db

              The signing secret is read from DMARC_WEBHOOK_SECRET, from stdin with
              --secret-stdin, or at a prompt. It is never taken as an argument.
            """);
        return 64;
    }
}
