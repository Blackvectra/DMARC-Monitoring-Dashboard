using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>What a backup run did.</summary>
/// <param name="Path">The file written, or null when nothing was.</param>
/// <param name="Bytes">Its size.</param>
/// <param name="Reports">Aggregate reports in the copy, counted from the copy itself.</param>
/// <param name="Records">Aggregate records in the copy.</param>
/// <param name="Removed">Older backups deleted to honour the retention count.</param>
public sealed record BackupResult(
    string? Path, long Bytes, long Reports, long Records, IReadOnlyList<string> Removed)
{
    public string Describe() =>
        Path is null
            ? "nothing was written"
            : $"{System.IO.Path.GetFileName(Path)}, {Bytes / 1024 / 1024} MB, "
              + $"{Reports:N0} reports and {Records:N0} records"
              + (Removed.Count > 0 ? $"; removed {Removed.Count} older" : "");
}

/// <summary>
/// Takes a verified copy of the database.
///
/// Nothing else here protects the data. `update.sh` and `rollback.sh` roll the
/// BINARY back; the reports have never had anything. On a single machine -
/// which is what this is designed to run on - that means the instance dying
/// takes years of a customer's history with it.
///
/// Three things separate this from `cp dmarc.db somewhere`:
///
///   It is consistent. The database is in WAL mode and a collector may be
///   mid-write; copying the file with cp catches a torn page and a -wal
///   alongside it that may or may not be the matching one. VACUUM INTO asks
///   SQLite for the copy, so it is a transactionally consistent snapshot
///   taken without stopping anything.
///
///   It is verified. A backup nobody has opened is a file, not a backup. Each
///   copy is opened, integrity-checked and counted before it is trusted, and
///   a copy that fails is deleted rather than left looking like a good one.
///
///   Retention never removes the last good copy. Pruning happens only after a
///   new backup has verified, so a run that fails leaves yesterday's alone.
/// </summary>
public sealed class BackupService(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>The prefix every backup this writes shares.</summary>
    internal const string Prefix = "dmarc-";

    /// <summary>Its extension. Deliberately not .db, so nothing points --db at one by accident.</summary>
    internal const string Extension = ".bak";

    /// <summary>The name a backup taken at this instant gets.</summary>
    /// <remarks>
    /// Sorts lexicographically in time order, which is what the retention
    /// sweep relies on rather than a filesystem timestamp - those survive a
    /// copy between machines badly, and the whole point of a backup is that it
    /// gets copied somewhere else.
    /// </remarks>
    internal static string NameFor(DateTimeOffset when) =>
        $"{Prefix}{when.UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}{Extension}";

    /// <summary>
    /// Writes a verified copy into <paramref name="directory"/>.
    /// </summary>
    /// <param name="keep">
    /// How many backups to leave behind, newest first. Must be at least one:
    /// a retention policy that can empty the directory is not one.
    /// </param>
    public async Task<BackupResult> RunAsync(
        string directory, int keep = 14, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, 1);

        if (!File.Exists(_databasePath))
        {
            throw new FileNotFoundException($"No database at {_databasePath}.", _databasePath);
        }

        Directory.CreateDirectory(directory);

        var target = Path.Combine(directory, NameFor(now ?? DateTimeOffset.UtcNow));

        // VACUUM INTO refuses to overwrite, which is the behaviour we want:
        // two runs in the same second must not silently leave one copy.
        if (File.Exists(target))
        {
            throw new IOException($"{target} already exists, so this run would overwrite a backup.");
        }

        await WriteCopyAsync(target, ct).ConfigureAwait(false);

        long reports, records;
        try
        {
            (reports, records) = await VerifyAsync(target, ct).ConfigureAwait(false);
        }
        catch
        {
            // A copy that cannot be verified is worse than no copy, because it
            // looks like one. Remove it, keep whatever was already there, and
            // let the exception reach the operator.
            TryDelete(target);
            throw;
        }

        // Only now that a good copy exists. A failed run must never be the
        // reason yesterday's backup went away.
        var removed = Prune(directory, keep);

        return new BackupResult(target, new FileInfo(target).Length, reports, records, removed);
    }

    /// <summary>
    /// The copy itself.
    /// </summary>
    /// <remarks>
    /// Read-only on the source: this must never be the thing that writes to a
    /// live database, and opening read-only also means a typo in the path
    /// reports rather than creating an empty file to back up.
    /// </remarks>
    private async Task WriteCopyAsync(string target, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();

        // Parameterised rather than interpolated. A path is operator input and
        // this is SQL; VACUUM INTO takes an expression, so a parameter works
        // and a quote in a directory name cannot end the statement.
        command.CommandText = "VACUUM INTO $target";
        command.Parameters.AddWithValue("$target", target);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens the copy and satisfies itself that it is a database with the data
    /// in it.
    /// </summary>
    /// <remarks>
    /// integrity_check alone is not enough. It would pass on a perfectly
    /// well-formed empty database, which is exactly what a backup of the wrong
    /// path looks like - so the tables are counted too, and the caller prints
    /// the numbers. An operator who reads "0 reports" in the log has learned
    /// something a silent success would have hidden.
    /// </remarks>
    private static async Task<(long Reports, long Records)> VerifyAsync(string target, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = target,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using (var check = db.CreateCommand())
        {
            check.CommandText = "PRAGMA integrity_check";
            var answer = (await check.ExecuteScalarAsync(ct).ConfigureAwait(false)) as string;
            if (!string.Equals(answer, "ok", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The copy at {target} did not pass an integrity check: {answer ?? "no answer"}");
            }
        }

        return (await CountAsync(db, "aggregate_reports", ct).ConfigureAwait(false),
                await CountAsync(db, "aggregate_records", ct).ConfigureAwait(false));
    }

    private static async Task<long> CountAsync(SqliteConnection db, string table, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table}";   // fixed names, never operator input
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Removes all but the newest <paramref name="keep"/> backups.
    /// </summary>
    /// <remarks>
    /// Matches on this service's own prefix and extension, and nothing else.
    /// A retention sweep that deleted by age alone would empty a directory
    /// somebody had also put something of their own in, and the directory it
    /// is pointed at is operator input.
    /// </remarks>
    internal static IReadOnlyList<string> Prune(string directory, int keep)
    {
        var removed = new List<string>();

        var ours = Directory
            .EnumerateFiles(directory, $"{Prefix}*{Extension}")
            .OrderByDescending(Path.GetFileName, StringComparer.Ordinal)
            .ToList();

        foreach (var old in ours.Skip(keep))
        {
            try
            {
                File.Delete(old);
                removed.Add(Path.GetFileName(old));
            }
            catch (IOException) { /* in use or gone; the next run tries again */ }
            catch (UnauthorizedAccessException) { }
        }

        return removed;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) { File.Delete(path); } }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
