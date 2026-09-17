using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Which DNS provider holds each client's zones, and the credential for it.
///
/// The credential never goes on the command line. Arguments end up in shell
/// history, in process listings and in the screenshot somebody attaches to a
/// ticket, so it is read from an environment variable, from stdin, or typed
/// at a prompt that does not echo. What is stored in the database is a
/// pointer; the token itself goes to the secret store.
/// </summary>
public static class DnsCommand
{
    private const string TokenVariable = "DMARC_DNS_SECRET";

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

        var secrets = new LocalSecretStore();
        var configs = new DnsProviderConfigs(dbPath, secrets);

        return action switch
        {
            "list" => await ListAsync(configs, ct).ConfigureAwait(false),
            "set" => await SetAsync(configs, rest, ct).ConfigureAwait(false),
            "remove" => await RemoveAsync(configs, rest, ct).ConfigureAwait(false),
            "test" => await TestAsync(configs, rest, ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc dns {action}"),
        };
    }

    private static async Task<int> ListAsync(DnsProviderConfigs configs, CancellationToken ct)
    {
        Console.WriteLine();
        Console.WriteLine($"  Secrets: {configs.Secrets.Description}");
        Console.WriteLine();

        var all = await configs.ListAsync(ct).ConfigureAwait(false);
        if (all.Count == 0)
        {
            Console.WriteLine("  No DNS providers configured. Fixes can be planned but not applied.");
            Console.WriteLine("  dmarc dns set --client <slug> --provider cloudflare --zone-id <id>");
            return 0;
        }

        foreach (var c in all)
        {
            var scope = c.Domain ?? $"every domain of {c.ClientSlug}";
            var coords = string.Join(", ", c.Settings.Select(kv => $"{kv.Key}={kv.Value}"));
            Console.WriteLine($"  {scope,-40} {c.Provider,-11} {coords}");
            if (c.CredentialRef is not null) { Console.WriteLine($"  {"",-40} credential {c.CredentialRef}"); }
            if (c.LastError is not null) { Console.WriteLine($"  {"",-40} last error: {c.LastError}"); }
        }
        Console.WriteLine();
        return 0;
    }

    private static async Task<int> SetAsync(DnsProviderConfigs configs, string[] args, CancellationToken ct)
    {
        var client = Args.Value(args, "--client");
        var provider = Args.Value(args, "--provider")?.ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(client) || string.IsNullOrWhiteSpace(provider))
        {
            return Usage("dmarc dns set --client <slug> [--domain <d>] --provider cloudflare|azuredns|manual ...");
        }

        var settings = new Dictionary<string, string>();
        void Take(string flag, string key)
        {
            if (Args.Value(args, flag) is { } v) { settings[key] = v; }
        }
        Take("--zone-id", "zone_id");
        Take("--subscription", "subscription_id");
        Take("--resource-group", "resource_group");
        Take("--zone", "zone");
        Take("--tenant-id", "tenant_id");
        Take("--client-id", "client_id");

        string? secret = null;
        var wantsSecret = provider == "cloudflare" || (provider == "azuredns" && settings.ContainsKey("client_id"));
        if (wantsSecret)
        {
            secret = await ReadSecretAsync(args, provider, ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(secret))
            {
                Console.Error.WriteLine($"No credential given. Set {TokenVariable}, pipe it with --secret-stdin, or run interactively to be prompted.");
                return 64;
            }
        }

        try
        {
            var config = await configs.SetAsync(client, Args.Value(args, "--domain"), provider, settings, secret, ct).ConfigureAwait(false);
            Console.WriteLine($"{config.Provider} set for {config.Domain ?? $"every domain of {client}"}.");
            if (config.CredentialRef is not null) { Console.WriteLine($"Credential stored as {config.CredentialRef}. {configs.Secrets.Description}"); }
            Console.WriteLine($"Check it: dmarc dns test --domain <domain>");
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    private static async Task<string?> ReadSecretAsync(string[] args, string provider, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(TokenVariable) is { Length: > 0 } fromEnv) { return fromEnv; }

        if (Args.Flag(args, "--secret-stdin"))
        {
            var line = await Console.In.ReadLineAsync(ct).ConfigureAwait(false);
            return line?.Trim();
        }

        if (Console.IsInputRedirected) { return null; }

        var what = provider == "cloudflare" ? "Cloudflare API token (Zone:DNS:Edit on this zone only)" : "client secret";
        Console.Write($"{what}: ");
        return ReadHidden();
    }

    /// <summary>Reads a line without echoing it, so it is not on the screen or in the scrollback.</summary>
    private static string ReadHidden()
    {
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

    private static async Task<int> RemoveAsync(DnsProviderConfigs configs, string[] args, CancellationToken ct)
    {
        var client = Args.Value(args, "--client");
        if (string.IsNullOrWhiteSpace(client)) { return Usage("dmarc dns remove --client <slug> [--domain <d>]"); }

        var removed = await configs.RemoveAsync(client, Args.Value(args, "--domain"), ct).ConfigureAwait(false);
        Console.WriteLine(removed ? "Removed, and its credential with it." : "Nothing was configured there.");
        return 0;
    }

    private static async Task<int> TestAsync(DnsProviderConfigs configs, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        if (string.IsNullOrWhiteSpace(domain)) { return Usage("dmarc dns test --domain <domain>"); }

        var config = await configs.ForDomainAsync(domain, ct).ConfigureAwait(false);
        if (config is null)
        {
            Console.WriteLine($"No provider is configured for {domain}. Fixes for it can be planned but not applied.");
            return 1;
        }

        try
        {
            var provider = await configs.BuildAsync(config, ct).ConfigureAwait(false);
            var records = await provider.GetRecordsAsync($"_dmarc.{domain}", "TXT", ct).ConfigureAwait(false);

            Console.WriteLine($"{config.Provider} answered for {domain}: {records.Count} TXT record(s) at _dmarc.{domain}.");
            foreach (var r in records) { Console.WriteLine($"  {r.Value}"); }
            await configs.MarkVerifiedAsync(config.Id, null, ct).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or Azure.RequestFailedException or DnsClient.DnsResponseException)
        {
            Console.Error.WriteLine($"{config.Provider} could not be used for {domain}: {ex.Message}");
            await configs.MarkVerifiedAsync(config.Id, ex.Message, ct).ConfigureAwait(false);
            return 1;
        }
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("""

              dmarc dns list
              dmarc dns set --client <slug> [--domain <d>] --provider cloudflare --zone-id <zone id>
              dmarc dns set --client <slug> [--domain <d>] --provider azuredns --subscription <id> --resource-group <rg> --zone <zone>
                            [--tenant-id <id> --client-id <id>]     app registration; otherwise the signed-in identity
              dmarc dns set --client <slug> [--domain <d>] --provider manual
              dmarc dns remove --client <slug> [--domain <d>]
              dmarc dns test --domain <domain>

              The credential is read from DMARC_DNS_SECRET, from stdin with --secret-stdin,
              or at a prompt. It is never taken as an argument.
            """);
        return 64;
    }
}
