using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Takes a verified copy of the database.
///
/// The only thing here that protects the reports. `dmarc update` and
/// rollback.sh roll the binary back; years of a customer's history had nothing
/// at all, on a product designed to run on one machine.
///
/// Safe to run while the collector is working - the copy comes from SQLite
/// rather than from the filesystem, so it is a consistent snapshot rather than
/// whatever the bytes happened to be mid-write.
/// </summary>
public static class BackupCommand
{
    private const int DefaultKeep = 14;

    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--to", "--keep", "!--quick") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var to = Args.Value(args, "--to");
        var keep = Args.Int(args, "--keep", DefaultKeep);
        var quick = Args.Flag(args, "--quick");

        if (string.IsNullOrWhiteSpace(to))
        {
            Console.Error.WriteLine("dmarc backup --to <directory> [--keep <n>] [--quick] [--db <path>]");
            Console.Error.WriteLine();
            Console.Error.WriteLine($"  Writes a verified copy and keeps the newest {DefaultKeep} by default.");
            Console.Error.WriteLine("  Put --to on a different disk from --db, or it protects against");
            Console.Error.WriteLine("  very little: the failure that takes the database usually takes");
            Console.Error.WriteLine("  everything beside it.");
            return 64;
        }

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }

        try
        {
            var result = await new BackupService(dbPath).RunAsync(to, keep, quick, null, ct).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine($"  {result.Describe()}");

            // Printed every run, not just an empty one. An operator who reads
            // "0 reports" in a log has learned something; a silent success
            // teaches nothing until the day it is restored.
            if (result.Records == 0)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("  That copy holds no report records. It verified as a database, so this is");
                Console.Error.WriteLine("  not corruption - check --db is the one the collector writes to.");
            }

            Console.WriteLine();
            return 0;
        }
        catch (InvalidDataException ex)
        {
            // Either the live database failed its check before anything was
            // written, or the copy failed afterwards and has been deleted.
            // Both leave the backups already held untouched, and both are
            // worth waking somebody for - this exit code is what systemd's
            // OnFailure= hangs off.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"  {ex.Message}");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Nothing was pruned, so every backup already held is still there.");
            return 74;   // EX_IOERR
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"  Could not write the backup: {ex.Message}");
            return 73;   // EX_CANTCREAT
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex)
        {
            // A full disk arrives as SQLITE_FULL from VACUUM INTO, and an
            // unwritable --to as SQLITE_CANTOPEN. Neither is a bug in this
            // program, and without this they fell through to Program.cs's
            // catch-all and were printed under a banner reading "This is a
            // bug" with a stack trace and exit 1 - the exact outcome the
            // corruption path was written to avoid, on the most ordinary
            // failure a nightly backup has.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"  Could not write the backup: {ex.Message}");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Nothing was pruned, so every backup already held is still there.");

            const int full = 13;   // SQLITE_FULL
            if (ex.SqliteErrorCode == full)
            {
                Console.Error.WriteLine("  The disk is full. Free space, or point --to somewhere with room.");
            }

            return 73;   // EX_CANTCREAT
        }
    }
}
