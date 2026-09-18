using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// The MTA-STS policy this product serves for a domain.
///
/// MTA-STS needs two things to agree, and only one of them is DNS. This is the
/// other one: the policy file, served at mta-sts.&lt;domain&gt; over HTTPS. The web
/// app serves it; this decides what it says.
///
/// The mail servers come from the domain's live MX records rather than being
/// typed, because the failure mode of getting them wrong is not a warning. In
/// enforce mode a sender that reaches a host the policy does not list gives up
/// rather than delivering, and keeps doing so until its cached copy expires.
/// </summary>
public static class MtaStsCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        var rest = args.Skip(1).ToArray();
        var dbPath = Args.Value(rest, "--db") ?? "dmarc.db";

        // Checking what a domain serves needs nothing but the internet, so it
        // works on a prospect's domain before they are a customer - which is
        // the commonest reason to run it.
        if (action == "check") { return await CheckAsync(rest, ct).ConfigureAwait(false); }

        if (!await new ReportStore(dbPath).IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        var store = new MtaStsStore(dbPath);

        return action switch
        {
            "list" => await ListAsync(store, ct).ConfigureAwait(false),
            "set" => await SetAsync(store, rest, ct).ConfigureAwait(false),
            "check" => await CheckAsync(rest, ct).ConfigureAwait(false),
            "remove" => await RemoveAsync(store, rest, ct).ConfigureAwait(false),
            _ => Usage($"Unknown: dmarc mta-sts {action}"),
        };
    }

    private static async Task<int> ListAsync(MtaStsStore store, CancellationToken ct)
    {
        var all = await store.ListAsync(ct).ConfigureAwait(false);

        Console.WriteLine();
        if (all.Count == 0)
        {
            Console.WriteLine("  No MTA-STS policies are being served.");
            Console.WriteLine("  dmarc mta-sts set --domain <domain>");
            Console.WriteLine();
            return 0;
        }

        foreach (var (domain, policy) in all)
        {
            Console.WriteLine($"  {domain,-28} {policy.Mode,-9} id {policy.Id}");
            foreach (var host in policy.Mx) { Console.WriteLine($"  {"",-28} mx {host}"); }
            Console.WriteLine($"  {"",-28} served at {MtaStsFetcher.UrlFor(domain)}");
            Console.WriteLine();
        }

        Console.WriteLine("  Each domain needs a CNAME: mta-sts.<domain> -> the host running this app.");
        Console.WriteLine();
        return 0;
    }

    private static async Task<int> SetAsync(MtaStsStore store, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        if (string.IsNullOrWhiteSpace(domain))
        {
            return Usage("dmarc mta-sts set --domain <domain> [--mode testing|enforce|none] [--mx <host>]...");
        }

        var mode = (Args.Value(args, "--mode") ?? MtaStsMode.Testing).ToLowerInvariant();

        // Taken from DNS unless given explicitly, because a typed list is a
        // list somebody can get wrong, and under enforce that is lost mail.
        var mx = Values(args, "--mx");
        if (mx.Count == 0)
        {
            var lookup = new DnsLookup();
            mx = [.. await lookup.MxAsync(domain, ct).ConfigureAwait(false)];

            if (mx.Count == 0)
            {
                Console.Error.WriteLine(
                    $"{domain} publishes no MX records this could read, so there is nothing to allow. "
                  + "Name them with --mx <host> if you are sure.");
                return 65;
            }

            Console.WriteLine($"  Mail servers, from {domain}'s MX records:");
            foreach (var host in mx) { Console.WriteLine($"    {host}"); }
            Console.WriteLine();
        }

        if (mode == MtaStsMode.Enforce && !Args.Flag(args, "--i-have-checked"))
        {
            // The one place this command can lose mail, so it is the one place
            // it insists on being told the check was done.
            Console.Error.WriteLine(
                "Refusing to write an enforcing policy without --i-have-checked.\n\n"
              + "Under enforce, a sender that reaches a mail server this policy does not list does not\n"
              + "deliver the message - and keeps refusing until its cached copy expires, whatever you\n"
              + "publish afterwards. Run 'dmarc fix --domain " + domain + "' first: it will say whether\n"
              + "TLS reports show senders connecting cleanly.");
            return 64;
        }

        try
        {
            var policy = await store.SetAsync(domain, mode, mx, Environment.UserName, ct: ct).ConfigureAwait(false);

            Console.WriteLine($"Serving a {policy.Mode} policy for {domain}, id {policy.Id}.");
            Console.WriteLine();
            Console.WriteLine(policy.ToFile().ReplaceLineEndings("\n"));
            Console.WriteLine($"Point mta-sts.{domain} at this host, then announce it:");
            Console.WriteLine($"  dmarc fix --domain {domain} --apply --reason \"...\"");
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 65;
        }
    }

    /// <summary>Fetches what is actually being served, the way a sender would.</summary>
    private static async Task<int> CheckAsync(string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        if (string.IsNullOrWhiteSpace(domain)) { return Usage("dmarc mta-sts check --domain <domain>"); }

        var served = await new MtaStsFetcher().FetchAsync(domain, ct: ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"  {MtaStsFetcher.UrlFor(domain)}");

        if (served.Policy is null)
        {
            Console.WriteLine($"    nothing usable: {served.Problem}");
            Console.WriteLine();
            return 1;
        }

        Console.WriteLine($"    mode {served.Policy.Mode}, max_age {served.Policy.MaxAgeSeconds}");
        foreach (var host in served.Policy.Mx) { Console.WriteLine($"    mx {host}"); }

        var mx = await new DnsLookup().MxAsync(domain, ct).ConfigureAwait(false);
        if (mx.Count > 0 && served.Policy.Uncovered(mx) is { Count: > 0 } missing)
        {
            Console.WriteLine();
            Console.WriteLine($"    does NOT cover {string.Join(", ", missing)}, which {domain} publishes as a mail server");
            Console.WriteLine(served.Policy.Mode == MtaStsMode.Enforce
                ? "    and the policy is enforcing, so mail to those servers is being refused"
                : "    harmless while testing, and mail to those would stop the moment it is enforced");
        }

        Console.WriteLine();
        return 0;
    }

    private static async Task<int> RemoveAsync(MtaStsStore store, string[] args, CancellationToken ct)
    {
        var domain = Args.Value(args, "--domain");
        if (string.IsNullOrWhiteSpace(domain)) { return Usage("dmarc mta-sts remove --domain <domain>"); }

        var removed = await store.RemoveAsync(domain, ct).ConfigureAwait(false);

        Console.WriteLine(removed
            ? $"No longer serving a policy for {domain}. Senders keep the last one until it expires, so "
              + $"remove the _mta-sts.{domain} TXT record too."
            : $"No policy was being served for {domain}.");
        return 0;
    }

    private static List<string> Values(string[] args, string name)
    {
        var values = new List<string>();
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            {
                values.Add(args[i + 1].Trim().TrimEnd('.').ToLowerInvariant());
            }
        }
        return values;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("""

              dmarc mta-sts list
              dmarc mta-sts set --domain <d> [--mode testing|enforce|none] [--mx <host>]...
                                The mail servers come from the domain's MX records unless
                                you name them. Starts in testing, which reports and
                                enforces nothing. --mode enforce needs --i-have-checked.
              dmarc mta-sts check --domain <d>
                                Fetch what is really being served, the way a sender does.
              dmarc mta-sts remove --domain <d>
            """);
        return 64;
    }
}
