using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Says which domains' reports can actually get back to the collector.
///
/// Both ways this breaks are silent. A reporter that looks for the RFC 7489
/// §7.1 authorization record and does not find it declines to send and tells
/// nobody, so a broken customer looks exactly like a quiet one. And a domain
/// whose rua points at a mailbox nothing collects produces nothing here while
/// its DNS looks perfect.
///
/// A standing check rather than a one-off, because this is the fault that
/// appears when somebody onboards a domain and forgets a step.
/// </summary>
public static class ReachabilityCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--domain", "!--quiet") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var domain = Args.Value(args, "--domain");
        var onlyProblems = Args.Flag(args, "--quiet");

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}. This checks the domains in "
                                  + "the book, so it needs one.");
            return 66;
        }

        var service = new ReachabilityService(dbPath);
        var domains = await service.RunAsync(domain, progress: null, ct: ct).ConfigureAwait(false);

        if (domains.Count == 0)
        {
            Console.Error.WriteLine(string.IsNullOrWhiteSpace(domain)
                ? "No domains in the database yet. Import some reports first."
                : $"{domain} is not in the book.");
            return 66;
        }

        var now = DateTimeOffset.UtcNow;
        var worst = 0;
        var clean = 0;

        Console.WriteLine();

        foreach (var reachability in domains)
        {
            ct.ThrowIfCancellationRequested();

            var findings = ReportReachability.Assess(reachability, now);

            if (findings.Count == 0)
            {
                clean++;
                if (!onlyProblems)
                {
                    Console.WriteLine($"  {reachability.Domain}");
                    Console.WriteLine($"    reports arriving: {Route(reachability)}");
                }

                continue;
            }

            Console.WriteLine($"  {reachability.Domain}");
            Console.WriteLine($"    {Route(reachability)}");

            foreach (var f in findings)
            {
                var label = f.Severity switch
                {
                    HygieneSeverity.Breaking => "BREAKING",
                    HygieneSeverity.Weakness => "weakness",
                    _ => "tidy",
                };

                Console.WriteLine($"    [{label}] {f.Problem}");
                Console.WriteLine($"              fix: {f.Fix}");
                if (f.Reference.Length > 0) { Console.WriteLine($"              per: {f.Reference}"); }
            }

            worst = Math.Max(worst, findings.Max(f => (int)f.Severity));
        }

        Console.WriteLine();
        Console.WriteLine($"  {clean} of {domains.Count} domain(s) are reporting into a mailbox this collects.");
        Console.WriteLine();

        return worst >= (int)HygieneSeverity.Breaking ? 1 : 0;
    }

    /// <summary>
    /// Where this domain's reports are asked to go, and what has arrived.
    /// </summary>
    /// <remarks>
    /// Printed for every domain including the clean ones, because the thing an
    /// operator is checking is that the address is the one they think it is.
    /// A domain reporting happily into somebody else's mailbox is clean by
    /// every measure here and still wrong.
    /// </remarks>
    internal static string Route(DomainReachability reachability)
    {
        ArgumentNullException.ThrowIfNull(reachability);

        if (reachability.DnsFailed) { return "DNS could not be read"; }

        var to = reachability.Destinations.Count == 0
            ? "nowhere - no rua"
            : string.Join(", ", reachability.Destinations.Select(d => d.Address));

        var held = reachability.ReportsHeld switch
        {
            0 => "nothing held",
            1 => "1 report held",
            var n => $"{n} reports held",
        };

        var last = reachability.LastReport is { } when
            ? $", newest {Days(DateTimeOffset.UtcNow - when)}"
            : "";

        return $"rua -> {to}; {held}{last}";
    }

    private static string Days(TimeSpan since) => (int)since.TotalDays switch
    {
        <= 0 => "today",
        1 => "yesterday",
        var d => $"{d} days ago",
    };
}
