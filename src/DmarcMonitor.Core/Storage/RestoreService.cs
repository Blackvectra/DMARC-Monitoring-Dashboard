using System.Globalization;
using System.IO.Compression;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>What putting a backup back did.</summary>
/// <param name="Database">The database now in place.</param>
/// <param name="ClientFiles">Client files restored beside it.</param>
/// <param name="Reports">Aggregate reports in what was restored, every file together.</param>
/// <param name="Records">Aggregate records in what was restored.</param>
/// <param name="Replaced">Where the database that was there before now is, or null when there was none.</param>
/// <param name="ReplacedClients">Where its client files now are, or null when it had none.</param>
/// <param name="Migration">What bringing the restored database up to date did.</param>
/// <param name="Reconcile">What putting its client files right against it did.</param>
public sealed record RestoreResult(
    string Database, int ClientFiles, long Reports, long Records,
    string? Replaced, string? ReplacedClients,
    MigrationResult Migration, ReconcileResult Reconcile);

/// <summary>
/// Puts a backup back: <c>dmarc restore</c>.
/// </summary>
/// <remarks>
/// <para>
/// A backup is a zip of the organization's database and every client's file,
/// laid out as they are on disk (see <see cref="BackupService"/>); one taken
/// before each client had a file of its own is a single SQLite database. Both
/// restore. Done by hand, a restore is four ways to lose data: a -wal left
/// beside the restored file is replayed onto it, a client folder left behind
/// disagrees with the database put back, a copy made over the live file
/// destroys it, and a zip entry named <c>../something</c> writes wherever it
/// likes. This does it in the one safe order:
/// </para>
/// <list type="number">
/// <item>
/// The backup is unpacked beside the database into a folder of its own, and
/// every entry's name is checked first: the database at the top, client files
/// one folder down, nothing else. A backup that is not shaped like one this
/// product wrote is refused whole.
/// </item>
/// <item>Every file unpacked is integrity-checked. Nothing live has been touched yet.</item>
/// <item>
/// The database in place - with its -wal and -shm, which belong to it and not
/// to the one being restored - and its client folder are moved aside,
/// never deleted: whatever they hold since the backup is not recoverable from
/// anywhere else.
/// </item>
/// <item>The unpacked files are moved into place: renames, on one filesystem.</item>
/// <item>
/// Migrations are applied - a backup from an older build is brought up to
/// date, one from before the split is split - and the client files are put
/// right against the organization's database, which among other things moves
/// the row id sequence past any id already in a file.
/// </item>
/// </list>
/// </remarks>
public sealed class RestoreService(string databasePath)
{
    private readonly string _databasePath = Path.GetFullPath(NotBlank(databasePath));

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static readonly byte[] SqliteHeader = "SQLite format 3\0"u8.ToArray();
    private static readonly byte[] ZipHeader = [0x50, 0x4B, 0x03, 0x04];

    /// <param name="backupPath">A .bak written by <c>dmarc backup</c>, or a single database file.</param>
    /// <param name="now">When this is, for the names the replaced files are kept under.</param>
    public async Task<RestoreResult> RunAsync(string backupPath, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath);
        var backup = Path.GetFullPath(backupPath);
        if (!File.Exists(backup)) { throw new FileNotFoundException($"No backup at {backup}.", backup); }

        var directory = Path.GetDirectoryName(_databasePath) ?? ".";
        var name = Path.GetFileNameWithoutExtension(_databasePath);
        var folder = ClientDatabases.FolderFor(_databasePath);
        var stamp = (now ?? DateTimeOffset.UtcNow).UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);

        Directory.CreateDirectory(directory);
        var staging = Path.Combine(directory, $"{name}.restoring-{stamp}");
        if (Directory.Exists(staging))
        {
            throw new IOException($"{staging} already exists: another restore is running, or one stopped part way. Look inside it, then remove it.");
        }

        ClientDatabases.CreateFolder(staging);
        var stagedDatabase = Path.Combine(staging, Path.GetFileName(_databasePath));
        var stagedFolder = Path.Combine(staging, Path.GetFileName(folder));

        string? replaced = null, replacedClients = null;
        int clientFiles;
        try
        {
            // ---- 1 and 2: unpack and check, touching nothing live ----------------
            clientFiles = await UnpackAsync(backup, stagedDatabase, stagedFolder, ct).ConfigureAwait(false);

            await CheckAsync(stagedDatabase, clientFile: false, ct).ConfigureAwait(false);
            if (Directory.Exists(stagedFolder))
            {
                foreach (var file in Directory.EnumerateFiles(stagedFolder, "*.db"))
                {
                    await CheckAsync(file, clientFile: true, ct).ConfigureAwait(false);
                }
            }

            await RefuseIfBeingWrittenAsync(ct).ConfigureAwait(false);
            SqliteConnection.ClearAllPools();

            // ---- 3: what is there now goes aside --------------------------------
            if (File.Exists(_databasePath))
            {
                replaced = Path.Combine(directory, $"{name}-replaced-{stamp}.db");
                File.Move(_databasePath, replaced);
                foreach (var sidecar in new[] { "-wal", "-shm" })
                {
                    if (File.Exists(_databasePath + sidecar)) { File.Move(_databasePath + sidecar, replaced + sidecar); }
                }
            }

            if (Directory.Exists(folder))
            {
                replacedClients = ClientDatabases.FolderFor(replaced ?? Path.Combine(directory, $"{name}-replaced-{stamp}.db"));
                Directory.Move(folder, replacedClients);
            }

            // ---- 4: and the backup takes its place -------------------------------
            var movedIn = false;
            try
            {
                File.Move(stagedDatabase, _databasePath);
                movedIn = true;
                if (Directory.Exists(stagedFolder)) { Directory.Move(stagedFolder, folder); }
            }
            catch
            {
                // Half in is worse than not at all: a restored database with
                // no client files, or the old ones. Back out, and put back
                // what was there.
                if (movedIn)
                {
                    try { File.Move(_databasePath, stagedDatabase); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
                PutBack(replaced, replacedClients, folder);
                throw;
            }
        }
        finally
        {
            try { if (Directory.Exists(staging)) { Directory.Delete(staging, recursive: true); } }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        // ---- 5: up to date, and the files agreeing with it -----------------------
        var migration = await DatabaseMigrations.ApplyAsync(_databasePath, ct).ConfigureAwait(false);
        var reconcile = await new ClientDatabases(_databasePath).ReconcileAsync(ct).ConfigureAwait(false);
        if (migration.Split is { } split) { clientFiles = split.Files; }

        var (reports, records) = await CountAsync(ct).ConfigureAwait(false);
        return new RestoreResult(_databasePath, clientFiles, reports, records, replaced, replacedClients, migration, reconcile);
    }

    /// <summary>
    /// Unpacks a backup into the staging folder, returning how many client
    /// files it held.
    /// </summary>
    private static async Task<int> UnpackAsync(string backup, string database, string folder, CancellationToken ct)
    {
        var header = new byte[16];
        int read;
        await using (var stream = File.OpenRead(backup))
        {
            read = await stream.ReadAsync(header, ct).ConfigureAwait(false);
        }

        if (read >= SqliteHeader.Length && header.AsSpan(0, SqliteHeader.Length).SequenceEqual(SqliteHeader))
        {
            // From before each client had a file of its own: the whole
            // database in one. The migrations split it once it is in place.
            File.Copy(backup, database);
            ClientDatabases.OwnerOnly(database, directory: false);
            return 0;
        }

        if (read < ZipHeader.Length || !header.AsSpan(0, ZipHeader.Length).SequenceEqual(ZipHeader))
        {
            throw new InvalidDataException($"{backup} is not a backup this product wrote: it is neither a database nor a zip of them.");
        }

        using var zip = ZipFile.OpenRead(backup);

        // Every name checked before anything is written, so a backup with one
        // bad entry writes nothing at all rather than everything up to it.
        string? top = null;
        string? clients = null;
        var files = new List<(ZipArchiveEntry Entry, string Name)>();

        foreach (var entry in zip.Entries)
        {
            // Either separator: a zip made elsewhere may use the other one, and
            // a "..\" must be caught as surely as a "../".
            var fullName = entry.FullName.Replace('\\', '/');
            if (fullName.EndsWith('/') && entry.Length == 0) { continue; }   // a folder's own entry

            var parts = fullName.Split('/');
            if (parts.Any(p => p.Length == 0 || p is "." or ".." || p.Contains(':', StringComparison.Ordinal))
                || !parts[^1].EndsWith(".db", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"{backup} holds {entry.FullName}, which is not where a backup this product wrote keeps anything. Nothing was restored.");
            }

            switch (parts.Length)
            {
                case 1 when top is null:
                    top = entry.FullName;
                    break;
                case 2 when parts[0].EndsWith("-clients", StringComparison.Ordinal) && (clients is null || clients == parts[0]):
                    clients = parts[0];
                    files.Add((entry, parts[1]));
                    break;
                default:
                    throw new InvalidDataException($"{backup} holds {entry.FullName}, which is not where a backup this product wrote keeps anything. Nothing was restored.");
            }
        }

        if (top is null)
        {
            throw new InvalidDataException($"{backup} holds no organization database. Nothing was restored.");
        }

        // Written under the names this database's own layout uses, whatever
        // the database was called where the backup was taken.
        await ExtractAsync(zip.GetEntry(top)!, database, ct).ConfigureAwait(false);

        if (files.Count > 0) { ClientDatabases.CreateFolder(folder); }
        foreach (var (entry, file) in files)
        {
            await ExtractAsync(entry, Path.Combine(folder, file), ct).ConfigureAwait(false);
        }

        return files.Count;
    }

    private static async Task ExtractAsync(ZipArchiveEntry entry, string path, CancellationToken ct)
    {
        await using var from = entry.Open();
        await using (var to = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        {
            await from.CopyToAsync(to, ct).ConfigureAwait(false);
        }
        ClientDatabases.OwnerOnly(path, directory: false);
    }

    /// <summary>A file from the backup, opened and checked before it goes anywhere near the live one.</summary>
    private static async Task CheckAsync(string path, bool clientFile, CancellationToken ct)
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
                check.CommandText = "PRAGMA integrity_check";
                if (await check.ExecuteScalarAsync(ct).ConfigureAwait(false) is not "ok")
                {
                    throw new InvalidDataException($"{Path.GetFileName(path)} in the backup did not pass an integrity check. Nothing was restored.");
                }
            }

            await using var shape = db.CreateCommand();
            shape.CommandText = clientFile
                ? "SELECT client_id FROM client_file LIMIT 1"
                : "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('clients', 'domains')";
            var answer = await shape.ExecuteScalarAsync(ct).ConfigureAwait(false);
            if (clientFile ? answer is not string : Convert.ToInt64(answer ?? 0L, CultureInfo.InvariantCulture) != 2)
            {
                throw new InvalidDataException($"{Path.GetFileName(path)} in the backup is not a DMARC Monitor database. Nothing was restored.");
            }
        }
        catch (SqliteException ex)
        {
            throw new InvalidDataException($"{Path.GetFileName(path)} in the backup could not be read ({ex.Message}). Nothing was restored.", ex);
        }
    }

    /// <summary>
    /// Refuses while something is writing to the database in place.
    /// </summary>
    /// <remarks>
    /// A collector part way through a report would go on writing into the file
    /// after it had been moved aside, and its report would be in neither. Only
    /// a writer can be seen this way - an idle dashboard holds nothing open -
    /// which is why the documented restore stops the services first.
    /// </remarks>
    private async Task RefuseIfBeingWrittenAsync(CancellationToken ct)
    {
        if (!File.Exists(_databasePath)) { return; }

        try
        {
            await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
                DefaultTimeout = 3,
            }.ToString());
            await db.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = db.BeginTransaction(deferred: false);
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode is 5 or 6)   // BUSY, LOCKED
        {
            throw new IOException($"{_databasePath} is being written to. Stop the dashboard and the collector first, then restore.", ex);
        }
        catch (SqliteException)
        {
            // Unreadable - which may be why it is being restored over. Moved
            // aside like any other, never opened again by this.
        }
    }

    /// <summary>Undoes step 3 when step 4 could not finish.</summary>
    private void PutBack(string? replaced, string? replacedClients, string folder)
    {
        try
        {
            if (replaced is not null && !File.Exists(_databasePath))
            {
                File.Move(replaced, _databasePath);
                foreach (var sidecar in new[] { "-wal", "-shm" })
                {
                    if (File.Exists(replaced + sidecar)) { File.Move(replaced + sidecar, _databasePath + sidecar); }
                }
            }

            if (replacedClients is not null && !Directory.Exists(folder))
            {
                Directory.Move(replacedClients, folder);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private async Task<(long Reports, long Records)> CountAsync(CancellationToken ct)
    {
        await using var db = await new ClientDatabases(_databasePath)
            .OpenAsync(ClientScope.Organization(null), ["aggregate_reports", "aggregate_records"], ct: ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM aggregate_reports), (SELECT COUNT(*) FROM aggregate_records)";
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        await reader.ReadAsync(ct).ConfigureAwait(false);
        return (reader.GetInt64(0), reader.GetInt64(1));
    }
}
