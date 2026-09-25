using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Puts a backup back: the organization's database and every client's file.
///
/// A backup is a zip of them, so the restore that used to be one cp is now a
/// job with four ways to lose data when done by hand - see RestoreService.
/// What was in place is moved aside, never deleted.
/// </summary>
public static class RestoreCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--from") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var from = Args.Value(args, "--from");

        if (string.IsNullOrWhiteSpace(from))
        {
            Console.Error.WriteLine("dmarc restore --from <backup.bak> [--db <path>]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Stop the dashboard and the collector first. The database in place, and its");
            Console.Error.WriteLine("  client files, are moved aside rather than deleted.");
            return 64;
        }

        if (!File.Exists(from))
        {
            Console.Error.WriteLine($"No backup at {Path.GetFullPath(from)}.");
            return 66;   // EX_NOINPUT
        }

        try
        {
            var result = await new RestoreService(dbPath).RunAsync(from, ct: ct).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine($"  Restored {result.Database} from {Path.GetFileName(from)}:");
            Console.WriteLine($"  {result.ClientFiles} client file(s), {result.Reports:N0} reports and {result.Records:N0} records.");

            if (result.Migration.Applied.Count > 0)
            {
                Console.WriteLine($"  Brought up to date: {string.Join(", ", result.Migration.Applied)}.");
            }
            if (result.Migration.Split is { } split)
            {
                Console.WriteLine($"  It was from before each client had a file of its own, so it was split: see {split.Backup}.");
            }
            foreach (var raised in result.Reconcile.RaisedSequences)
            {
                Console.WriteLine($"  Row ids for {raised}.");
            }

            if (result.Replaced is not null)
            {
                Console.WriteLine();
                Console.WriteLine($"  What was there before is kept at {result.Replaced}");
                if (result.ReplacedClients is not null)
                {
                    Console.WriteLine($"  with its client files at {result.ReplacedClients}");
                }
                Console.WriteLine("  Delete them once the dashboard shows what it should.");
            }

            Console.WriteLine();
            return 0;
        }
        catch (InvalidDataException ex)
        {
            // The backup: not ours, damaged, or shaped wrongly. Nothing live
            // has been touched when this is thrown.
            Console.Error.WriteLine($"  {ex.Message}");
            return 65;   // EX_DATAERR
        }
        catch (DatabaseNotSplitException ex)
        {
            Console.Error.WriteLine($"  Restored, but it could not be brought up to date: {ex.Message}");
            return 70;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"  Could not restore: {ex.Message}");
            Console.Error.WriteLine("  Stop the dashboard and the collector, then try again. Whatever was in place");
            Console.Error.WriteLine("  when this stopped has been put back where it was.");
            return 75;   // EX_TEMPFAIL
        }
    }
}
