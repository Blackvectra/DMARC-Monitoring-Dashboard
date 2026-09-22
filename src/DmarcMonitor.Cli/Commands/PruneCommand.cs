using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Removes report data past its retention window.
///
/// The schema has assumed a retention window since it was written and nothing
/// enforced one, so both report tables grew without bound. Beyond disk that
/// matters for one reason above the others: forensic reports hold real message
/// headers, and keeping them for ever turns a monitoring tool into a mail
/// archive nobody agreed to.
///
/// A dry run unless --apply, like every other command here that changes
/// something somebody would miss.
/// </summary>
public static class PruneCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--aggregate-days", "--forensic-days", "--by", "!--apply")
            is var bad and not 0)
        {
            return bad;
        }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var apply = Args.Flag(args, "--apply");

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }

        var defaults = new RetentionPolicy();
        var policy = new RetentionPolicy
        {
            AggregateDays = Args.Int(args, "--aggregate-days", defaults.AggregateDays),
            ForensicDays = Args.Int(args, "--forensic-days", defaults.ForensicDays),
        };

        if (!policy.IsValid)
        {
            Console.Error.WriteLine("That retention policy will not do:");
            foreach (var problem in policy.Problems) { Console.Error.WriteLine($"  {problem}"); }
            return 64;
        }

        var service = new RetentionService(dbPath);
        var now = DateTimeOffset.UtcNow;

        Console.WriteLine();
        Console.WriteLine($"  Keeping: {policy}");
        Console.WriteLine($"  Aggregate and TLS reports older than {policy.AggregateCutoff(now)} UTC");
        Console.WriteLine($"  Forensic reports older than {policy.ForensicCutoff(now)} UTC");
        Console.WriteLine();

        var preview = await service.PreviewAsync(policy, now, ct).ConfigureAwait(false);

        if (preview.NothingToDo)
        {
            Console.WriteLine("  Nothing is old enough to remove.");
            Console.WriteLine();
            return 0;
        }

        if (!apply)
        {
            Console.WriteLine($"  {preview.Describe()}");
            Console.WriteLine();
            Console.WriteLine("  Nothing was removed. Add --apply to do it.");
            Console.WriteLine();
            return 0;
        }

        var by = Args.Value(args, "--by") ?? Environment.UserName;
        var audit = new AuditLog(dbPath);
        var result = await service.ApplyAsync(policy, now, by, audit, ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"  {result.Describe()}.");
        Console.WriteLine("  Recorded in the audit log.");

        // SQLite does not hand the space back to the filesystem on delete. Not
        // done automatically: VACUUM rewrites the whole database and needs room
        // for a second copy of it, which is the wrong thing to do to somebody's
        // disk without being asked.
        Console.WriteLine();
        Console.WriteLine("  The file will not shrink until the database is compacted. When there is room");
        Console.WriteLine("  for a second copy of it, and nothing else is using it:");
        Console.WriteLine($"    sqlite3 {dbPath} VACUUM");
        Console.WriteLine();

        return 0;
    }
}
