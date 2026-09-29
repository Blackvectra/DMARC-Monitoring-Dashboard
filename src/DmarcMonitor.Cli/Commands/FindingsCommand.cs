using DmarcMonitor.Core.Findings;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// The findings engines that work from what is stored, with no network: what
/// the reports say about each domain, whether an applied change has shown
/// up in the receivers' reports, and which exceptions have run out.
/// </summary>
/// <remarks>
/// Run nightly after the DNS scan (dmarc-dns.service's third step), before
/// dmarc-notify sends what was raised. Exits 0 when it ran; what it found is
/// in the findings, and dmarc health is what judges them.
/// </remarks>
public static class FindingsCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var sub = args.Length > 0 ? args[0].ToLowerInvariant() : "";
        var rest = args.Skip(1).ToArray();

        return sub switch
        {
            "observe" => await ObserveAsync(rest, ct).ConfigureAwait(false),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("dmarc findings observe [--db <path>]    what the stored reports say, applied changes shown in force, exceptions run out");
        return 64;
    }

    private static async Task<int> ObserveAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db") is var bad and not 0) { return bad; }
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }
        if (!await SchemaGuard.IsCurrentAsync(dbPath, ct).ConfigureAwait(false)) { return 69; }

        var observed = await new ReportsFindingSource(dbPath).ObserveAllAsync(ct: ct).ConfigureAwait(false);
        if (observed.Count == 0) { Console.WriteLine("No organizations in the database yet."); }
        foreach (var org in observed)
        {
            Console.WriteLine(org.NotObserved is { } why
                ? $"{org.Organization}: reports not observed, {why}" + (org.Unknown > 0 ? $"; {org.Unknown} open finding(s) are now unknown" : "")
                : $"{org.Organization}: {org.Quiet} domain(s) quiet after reporting regularly; {org.Reporting} with an open finding reported on again");
        }

        var verified = await new RemediationFindingSource(dbPath).CheckEffectivenessAsync(ct: ct).ConfigureAwait(false);
        Console.WriteLine($"{verified} applied change(s) resolved: shown in force by a receiver's report, or fourteen days past DNS verification");

        var expired = await new FindingLifecycle(dbPath).ExpireExceptionsAsync(ct: ct).ConfigureAwait(false);
        Console.WriteLine($"{expired} exception(s) expired and their findings back in the queue");
        return 0;
    }
}
