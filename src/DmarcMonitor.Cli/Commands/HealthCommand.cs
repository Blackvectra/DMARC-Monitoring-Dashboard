using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Says whether this install is still doing its job.
///
/// Everything it looks at fails silently. A collector whose certificate
/// expired stops storing reports and says nothing; the pages go on showing the
/// figures from before it stopped, and those figures look fine. A customer
/// whose DMARC record somebody else edited stops being reported on at all, and
/// an empty chart reads as "no problems" rather than "no data".
///
/// Exits non-zero when something is broken, which is the whole point: that is
/// what systemd's OnFailure= and cron's mail-on-output hang off, so this needs
/// no SMTP configuration of its own to become an alert.
/// </summary>
public static class HealthCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--backups", "!--quiet") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var backups = Args.Value(args, "--backups");
        var onlyProblems = Args.Flag(args, "--quiet");

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }

        var facts = await new HealthService(dbPath)
            .GatherAsync(backups, null, ct)
            .ConfigureAwait(false);

        var findings = HealthCheck.Assess(facts, DateTimeOffset.UtcNow);

        if (findings.Count == 0)
        {
            // Stays silent under --quiet so a scheduled run mails nothing on a
            // good day. A health check that writes every hour is one nobody
            // reads on the hour it matters.
            if (!onlyProblems)
            {
                Console.WriteLine();
                Console.WriteLine("  Nothing wrong.");
                foreach (var org in facts.Collection)
                {
                    var name = string.IsNullOrWhiteSpace(org.Organization) ? "local" : org.Organization;
                    Console.WriteLine(
                        $"    {name}: {org.Domains} domain(s), {org.StoredLastDay} report(s) stored today"
                        + (org.LastStored is { } when ? $", newest {Ago(DateTimeOffset.UtcNow - when)}" : ""));
                }

                if (facts.LastBackup is { } backup)
                {
                    Console.WriteLine($"    backup: newest {Ago(DateTimeOffset.UtcNow - backup)}");
                }

                Console.WriteLine();
            }

            return 0;
        }

        // To stderr, so a cron job that mails output mails only the problems
        // and a run with nothing wrong is silent.
        Console.Error.WriteLine();

        foreach (var f in findings)
        {
            var label = f.Severity switch
            {
                HygieneSeverity.Breaking => "BROKEN",
                HygieneSeverity.Weakness => "check ",
                _ => "tidy  ",
            };

            Console.Error.WriteLine($"  [{label}] {f.Problem}");
            Console.Error.WriteLine($"            fix: {f.Fix}");
            Console.Error.WriteLine();
        }

        var worst = findings.Max(f => f.Severity);

        // 1 for something actually broken, 0 for anything softer. A weakness
        // that exits non-zero every night trains an operator to ignore the
        // alert, and then the breaking one arrives into a muted channel.
        return worst >= HygieneSeverity.Breaking ? 1 : 0;
    }

    private static string Ago(TimeSpan since) => since.TotalDays switch
    {
        >= 2 => $"{(int)since.TotalDays} days ago",
        >= 1 => "yesterday",
        _ when since.TotalHours >= 1 => $"{(int)since.TotalHours}h ago",
        _ => "just now",
    };
}
