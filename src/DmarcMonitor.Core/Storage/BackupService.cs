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
/// Takes a verified copy of the database and every client's file.
///
/// A backup is one .bak file, as it has always been, but since each client has
/// a database file of its own it is a zip holding them all, laid out as they
/// are beside each other on disk: the organization's database, and its client
/// folder. Restoring is putting them back (dmarc restore). A .bak from before
/// the split is a single SQLite database, and restores the same way.
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
///   SQLite for the copy, so each file is a transactionally consistent
///   snapshot taken without stopping anything. The client files are copied
///   before the organization's database, so every report in the backup has
///   its domain in it: a domain is always recorded before its first report.
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
    /// <param name="quick">
    /// Use PRAGMA quick_check on the source instead of integrity_check.
    /// Roughly nine times faster - measured at 424ms against 3.8s on a 313 MB
    /// database - and it skips exactly the part worth having: whether each
    /// index still agrees with the table it indexes. Worth reaching for only
    /// when the full check has actually become too slow to run nightly, which
    /// on the numbers above is a long way off.
    /// </param>
    public async Task<BackupResult> RunAsync(
        string directory, int keep = 14, bool quick = false,
        DateTimeOffset? now = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, 1);

        if (!File.Exists(_databasePath))
        {
            throw new FileNotFoundException($"No database at {_databasePath}.", _databasePath);
        }

        // BEFORE anything is written or removed.
        //
        // Checking only the copy - which is what this did at first - leaves the
        // worse failure uncovered. A database that has begun to corrupt still
        // copies, and the copy verifies, because it is a faithful copy of
        // damaged pages. Fourteen nights later every backup held is a copy of
        // the damage and the last good one has been pruned away, on schedule,
        // by this service.
        //
        // So the source is checked first and a failure stops the run dead:
        // nothing is written, and - the point - nothing is PRUNED. Whatever
        // good backups exist stay exactly where they are, and the non-zero
        // exit puts it in front of somebody the same night.
        var files = new ClientDatabases(_databasePath);
        var clientFiles = await ClientFilesAsync(files, ct).ConfigureAwait(false);

        await CheckSourceAsync(_databasePath, quick, ct).ConfigureAwait(false);
        foreach (var file in clientFiles)
        {
            await CheckSourceAsync(file, quick, ct).ConfigureAwait(false);
        }

        Directory.CreateDirectory(directory);
        RestrictToOwner(directory, isDirectory: true);

        var target = Path.Combine(directory, NameFor(now ?? DateTimeOffset.UtcNow));

        // Never overwrite: two runs in the same second must not silently
        // leave one copy.
        if (File.Exists(target))
        {
            throw new IOException($"{target} already exists, so this run would overwrite a backup.");
        }

        var staging = target + ".partial";
        long reports = 0, records = 0;

        try
        {
            if (Directory.Exists(staging)) { Directory.Delete(staging, recursive: true); }
            Directory.CreateDirectory(staging);
            RestrictToOwner(staging, isDirectory: true);

            var registryName = Path.GetFileName(files.RegistryPath);
            var folderName = Path.GetFileName(files.Folder);

            // Client files first, the organization's database last: see the
            // class remarks.
            if (clientFiles.Count > 0) { Directory.CreateDirectory(Path.Combine(staging, folderName)); }
            foreach (var file in clientFiles)
            {
                var copy = Path.Combine(staging, folderName, Path.GetFileName(file));
                await WriteCopyAsync(file, copy, ct).ConfigureAwait(false);
                var (r, n) = await VerifyAsync(copy, clientFile: true, ct).ConfigureAwait(false);
                reports += r;
                records += n;
            }

            var registryCopy = Path.Combine(staging, registryName);
            await WriteCopyAsync(_databasePath, registryCopy, ct).ConfigureAwait(false);
            var (legacyReports, legacyRecords) = await VerifyAsync(registryCopy, clientFile: false, ct).ConfigureAwait(false);
            reports += legacyReports;
            records += legacyRecords;

            // One file, written under a temporary name and renamed, so a run
            // that dies part way never leaves a .bak that looks whole.
            var zipping = target + ".zipping";
            System.IO.Compression.ZipFile.CreateFromDirectory(
                staging, zipping, System.IO.Compression.CompressionLevel.Optimal, includeBaseDirectory: false);
            File.Move(zipping, target);
        }
        catch
        {
            // A copy that cannot be verified is worse than no copy, because it
            // looks like one; a truncated file is a fresh timestamp that makes
            // the health check report a backup that was never taken. Remove
            // what was made, keep whatever was already there, and let the
            // exception reach the operator.
            TryDelete(target + ".zipping");
            TryDelete(target);
            throw;
        }
        finally
        {
            try { if (Directory.Exists(staging)) { Directory.Delete(staging, recursive: true); } }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        RestrictToOwner(target);

        // Only now that a good copy exists. A failed run must never be the
        // reason yesterday's backup went away.
        var removed = Prune(directory, keep);

        return new BackupResult(target, new FileInfo(target).Length, reports, records, removed);
    }

    /// <summary>
    /// Satisfies itself that the LIVE database is sound before copying it.
    /// </summary>
    /// <remarks>
    /// Read-only, and cheap enough to do every night: 100ms on a 17 MB
    /// database and 3.8s on a 313 MB one, which is about thirty years of a
    /// seventeen-domain book. It takes a read lock, so a collector writing at
    /// the same time waits rather than fails - the same retry that makes two
    /// collectors safe.
    /// </remarks>
    private static async Task CheckSourceAsync(string path, bool quick, CancellationToken ct)
    {
        try
        {
            await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

            await db.OpenAsync(ct).ConfigureAwait(false);

            await using (var check = db.CreateCommand())
            {
                check.CommandText = quick ? "PRAGMA quick_check" : "PRAGMA integrity_check";
                var answer = (await check.ExecuteScalarAsync(ct).ConfigureAwait(false)) as string;

                if (!string.Equals(answer, "ok", StringComparison.Ordinal))
                {
                    throw Corrupt(path, answer ?? "it gave no answer");
                }
            }

            // Cheap - 14ms on the real database, 6ms on a 313 MB one - and it
            // catches something integrity_check does not look for at all: a
            // record pointing at a report that is no longer there. That is not
            // page corruption, it is data that has lost its meaning, and it is
            // worth knowing before it is copied forward another fourteen nights.
            await using (var keys = db.CreateCommand())
            {
                keys.CommandText = "PRAGMA foreign_key_check";
                await using var reader = await keys.ExecuteReaderAsync(ct).ConfigureAwait(false);

                if (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    var table = reader.IsDBNull(0) ? "a table" : reader.GetString(0);
                    throw Corrupt(path, $"rows in {table} point at parents that are no longer there");
                }
            }
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode is Corrupted or NotADatabase)
        {
            // SQLite does not always ANSWER an integrity check - damage bad
            // enough and the check itself fails with SQLITE_CORRUPT. Both mean
            // the same thing here, and the difference must not leak: unhandled,
            // this reaches Program.cs's catch-all and is printed under a banner
            // reading "This is a bug" with a stack trace, when it is a finding
            // about somebody's disk and has a real answer - restore from the
            // newest backup, which this run has deliberately not touched.
            throw Corrupt(path, ex.Message);
        }
    }

    /// <summary>SQLITE_CORRUPT: the file is a database and is damaged.</summary>
    private const int Corrupted = 11;

    /// <summary>SQLITE_NOTADB: the file is not a database at all.</summary>
    private const int NotADatabase = 26;

    /// <summary>
    /// The one message, however the damage announced itself.
    /// </summary>
    /// <remarks>
    /// Read at 03:20 by somebody who has just been paged, so it says what is
    /// safe before it says what is wrong. The backups already held are the
    /// whole reason this check runs before the copy rather than after it.
    /// </remarks>
    private static InvalidDataException Corrupt(string path, string because) =>
        new($"The database at {path} did not pass an integrity check: {because}. "
            + "No backup was taken and nothing was removed, so every backup already held is still "
            + "there - restore from the newest one rather than letting tonight's run replace it.");

    /// <summary>
    /// The copy itself.
    /// </summary>
    /// <remarks>
    /// Read-only on the source: this must never be the thing that writes to a
    /// live database, and opening read-only also means a typo in the path
    /// reports rather than creating an empty file to back up.
    /// </remarks>
    private static async Task WriteCopyAsync(string source, string target, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = source,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
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
    private static async Task<(long Reports, long Records)> VerifyAsync(string target, bool clientFile, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = target,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
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

        // The organization's database holds no reports once it is split; one
        // that has not been yet still does, and its copy is counted like any.
        if (!clientFile && !await HasTableAsync(db, "aggregate_reports", ct).ConfigureAwait(false))
        {
            return (0, 0);
        }

        return (await CountAsync(db, "aggregate_reports", ct).ConfigureAwait(false),
                await CountAsync(db, "aggregate_records", ct).ConfigureAwait(false));
    }

    private static async Task<bool> HasTableAsync(SqliteConnection db, string table, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $t";
        command.Parameters.AddWithValue("$t", table);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

    /// <summary>
    /// Every database file in the client folder: each client's, and any rows
    /// the split kept aside because their client was gone.
    /// </summary>
    /// <remarks>
    /// Whatever is in the folder rather than whatever the client list names, so
    /// nothing held is left out of a backup because the list and the folder
    /// disagree - the backup is where a disagreement gets looked into from.
    /// </remarks>
    private static Task<IReadOnlyList<string>> ClientFilesAsync(ClientDatabases files, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        IReadOnlyList<string> found = Directory.Exists(files.Folder)
            ? [.. Directory.EnumerateFiles(files.Folder, "*.db").OrderBy(f => f, StringComparer.Ordinal)]
            : [];
        return Task.FromResult(found);
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

    /// <summary>
    /// Takes a backup's permissions down to the owner alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A backup is a complete copy of every client's data, and until this
    /// existed it was written with whatever the process umask gave it - 0644
    /// on an ordinary server, in a directory created 0755. The live database
    /// is 0600. So taking a backup silently DOWNGRADED the protection on the
    /// data: any local account on the box could read the copy, and the nightly
    /// timer made a fresh one every night.
    /// </para>
    /// <para>
    /// Set after the file exists rather than through the umask, because VACUUM
    /// INTO is what creates it and SQLite does not offer a mode. That leaves a
    /// window of milliseconds at 0644; the directory being 0700 is what closes
    /// it, which is why that is set first and before anything is written into
    /// it.
    /// </para>
    /// <para>
    /// Unix only. Windows inherits the parent directory's ACL, which for a
    /// service account's own folder is already restrictive, and there is no
    /// mode to set. Failing to tighten permissions must never fail the backup
    /// itself - a copy that exists and is readable is worth more than no copy.
    /// </para>
    /// </remarks>
    private static void RestrictToOwner(string path, bool isDirectory = false)
    {
        if (OperatingSystem.IsWindows()) { return; }

        try
        {
            var mode = isDirectory
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute   // 0700
                : UnixFileMode.UserRead | UnixFileMode.UserWrite;                             // 0600

            File.SetUnixFileMode(path, mode);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Left as the umask made it. The copy is still taken, and the
            // operator's own tooling may have its own view of the directory.
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) { File.Delete(path); } }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
