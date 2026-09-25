using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>What splitting a single database into client files did.</summary>
/// <param name="Files">How many client files were written.</param>
/// <param name="Rows">How many rows were moved into them, all tables together.</param>
/// <param name="Backup">The copy of the database as it was, left beside it.</param>
/// <param name="Unfiled">
/// Rows whose client no longer exists, kept in a file of their own rather than
/// dropped. Zero on any database this product has kept consistent.
/// </param>
/// <param name="SetAside">A client folder an interrupted earlier attempt left, moved aside rather than deleted.</param>
public sealed record SplitResult(int Files, long Rows, string Backup, long Unfiled, string? SetAside);

/// <summary>
/// Migration 0019: the single database becomes the organization's database
/// plus one file per client.
/// </summary>
/// <remarks>
/// <para>
/// The one migration that moves data rather than adding somewhere to put it,
/// so it is careful in the ways the others need not be:
/// </para>
/// <list type="number">
/// <item>A copy of the database as it was is written beside it first.</item>
/// <item>
/// It runs inside the migration's own transaction on the organization's
/// database, begun IMMEDIATE, so no other writer - a collector of the old
/// version still running, say - can add a row between it being copied and
/// its table being dropped.
/// </item>
/// <item>
/// The files are written into a staging folder, every table is counted in
/// both places, and only if the counts agree is the folder renamed into place
/// and the tables dropped. Anything else throws, the transaction rolls back,
/// and the database is exactly as it was.
/// </item>
/// <item>
/// A folder left by an attempt that was interrupted after the rename is moved
/// aside, not deleted: the organization's database still holds every row,
/// since the drop never committed, so the files are rebuilt from it.
/// </item>
/// </list>
/// </remarks>
internal static class ClientFileSplit
{
    public const string Version = "0019";

    /// <param name="registry">
    /// The organization's database, inside the migration's transaction. Rows
    /// are read through a second, read-only connection, which in WAL mode sees
    /// the database as it stood when the transaction began.
    /// </param>
    public static async Task<SplitResult> RunAsync(
        string registryPath, SqliteConnection registry, SqliteTransaction transaction, string backup, CancellationToken ct)
    {
        var files = new ClientDatabases(registryPath);
        var tables = ClientDatabases.Tables;

        // What there is to move, counted inside the transaction.
        var before = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var table in tables)
        {
            before[table] = await CountAsync(registry, transaction, table, ct).ConfigureAwait(false);
        }

        var clients = new List<ClientFile>();
        await using (var list = registry.CreateCommand())
        {
            list.Transaction = transaction;
            list.CommandText = "SELECT id, slug, tenant_id FROM clients ORDER BY id";
            await using var reader = await list.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                clients.Add(new ClientFile(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
            }
        }

        // A folder already at the final name can only be from an attempt that
        // renamed it and then failed to commit - 0019 is not recorded, or this
        // would not be running - so its contents are older than what the
        // database holds. Moved aside for whoever wants to look, never deleted.
        string? setAside = null;
        if (Directory.Exists(files.Folder))
        {
            setAside = $"{files.Folder}.set-aside-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}";
            Directory.Move(files.Folder, setAside);
        }

        var staging = files.Folder + ".partial";
        if (Directory.Exists(staging)) { Directory.Delete(staging, recursive: true); }
        ClientDatabases.CreateFolder(staging);

        try
        {
            var after = tables.ToDictionary(t => t, _ => 0L, StringComparer.Ordinal);
            var written = 0;

            foreach (var client in clients)
            {
                ct.ThrowIfCancellationRequested();

                var path = Path.Combine(staging, Path.GetFileName(files.PathFor(client)));
                var moved = await CopyAsync(registryPath, path, client, "client_id = $id", client.Id, ct).ConfigureAwait(false);

                // A client with nothing stored gets no file yet; one is made
                // the first time anything is written for it.
                if (moved.Values.Sum() == 0)
                {
                    ClientDatabases.DeleteFileAndJournals(path);
                    continue;
                }

                foreach (var (table, count) in moved) { after[table] += count; }
                written++;
            }

            // Rows whose client is gone. None on a database this product kept,
            // because every client table's client_id is a foreign key or is
            // erased with its client - but a database edited by hand, or by an
            // older build, is not something to lose rows from on the way past.
            long unfiled = 0;
            if (tables.Any(t => after[t] < before[t]))
            {
                var orphans = new ClientFile("unfiled", "unfiled", "");
                var path = Path.Combine(staging, "unfiled-rows.db");
                var moved = await CopyAsync(registryPath, path, orphans,
                    "client_id IS NULL OR client_id NOT IN (SELECT id FROM src.clients)", null, ct).ConfigureAwait(false);
                foreach (var (table, count) in moved) { after[table] += count; }
                unfiled = moved.Values.Sum();
                if (unfiled == 0) { ClientDatabases.DeleteFileAndJournals(path); }
            }

            var wrong = tables.Where(t => after[t] != before[t]).ToList();
            if (wrong.Count > 0)
            {
                throw new InvalidOperationException(
                    "The client files do not hold every row, so nothing was changed: "
                    + string.Join("; ", wrong.Select(t => $"{t} has {before[t]:N0} rows here and {after[t]:N0} in the files")));
            }

            SqliteConnection.ClearAllPools();
            Directory.Move(staging, files.Folder);

            return new SplitResult(written, after.Values.Sum(), backup, unfiled, setAside);
        }
        catch
        {
            SqliteConnection.ClearAllPools();
            try { if (Directory.Exists(staging)) { Directory.Delete(staging, recursive: true); } }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            throw;
        }
    }

    /// <summary>
    /// Writes one client's rows into a new client file, returning how many
    /// of each table it wrote.
    /// </summary>
    private static async Task<Dictionary<string, long>> CopyAsync(
        string registryPath, string path, ClientFile client, string filter, string? clientId, CancellationToken ct)
    {
        await ClientDatabases.CreateAtAsync(path, client, ct).ConfigureAwait(false);

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = ClientDatabases.SqliteUri(path, readOnly: false),
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);

        // Parents and children arrive table by table in schema order, which is
        // not always parent first (aggregate_records names senders, created
        // after it), so the keys are checked once at the end instead.
        await ExecuteAsync(db, "PRAGMA foreign_keys = OFF", ct).ConfigureAwait(false);

        await using (var attach = db.CreateCommand())
        {
            attach.CommandText = "ATTACH DATABASE $file AS src";
            attach.Parameters.AddWithValue("$file", ClientDatabases.SqliteUri(registryPath, readOnly: true));
            await attach.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        var moved = new Dictionary<string, long>(StringComparer.Ordinal);

        await ExecuteAsync(db, "BEGIN", ct).ConfigureAwait(false);
        foreach (var table in ClientDatabases.Tables)
        {
            var shared = (await ColumnsAsync(db, "main", table, ct).ConfigureAwait(false))
                .Intersect(await ColumnsAsync(db, "src", table, ct).ConfigureAwait(false), StringComparer.OrdinalIgnoreCase)
                .ToList();
            var columns = string.Join(", ", shared);

            await using var copy = db.CreateCommand();
            copy.CommandText = $"INSERT INTO main.{table} ({columns}) SELECT {columns} FROM src.{table} WHERE {filter}";
            if (clientId is not null) { copy.Parameters.AddWithValue("$id", clientId); }
            moved[table] = await copy.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        // A reference that pointed at another client's row - never written by
        // this product, but a hand-edited database is not refused for it - is
        // cleared rather than left dangling, the same as ON DELETE SET NULL
        // would have done had that row been deleted.
        await ExecuteAsync(db, """
            UPDATE aggregate_records SET sender_id = NULL
             WHERE sender_id IS NOT NULL AND sender_id NOT IN (SELECT id FROM senders);
            UPDATE dns_change_plans SET sender_id = NULL
             WHERE sender_id IS NOT NULL AND sender_id NOT IN (SELECT id FROM senders);
            UPDATE dns_changes SET plan_id = NULL
             WHERE plan_id IS NOT NULL AND plan_id NOT IN (SELECT id FROM dns_change_plans);
            """, ct).ConfigureAwait(false);
        await ExecuteAsync(db, "COMMIT", ct).ConfigureAwait(false);

        await using (var check = db.CreateCommand())
        {
            check.CommandText = "SELECT \"table\" FROM pragma_foreign_key_check LIMIT 1";
            if (await check.ExecuteScalarAsync(ct).ConfigureAwait(false) is string broken)
            {
                throw new InvalidOperationException(
                    $"{client.Slug}'s rows in {broken} refer to rows that are not theirs, so nothing was changed.");
            }
        }

        await ExecuteAsync(db, "DETACH DATABASE src", ct).ConfigureAwait(false);
        return moved;
    }

    /// <summary>
    /// A copy of the database as it stands, beside it, before anything moves.
    /// </summary>
    /// <remarks>
    /// VACUUM INTO writes a consistent copy while the database stays open, and
    /// the copy is a normal database file: renaming it back is the whole of
    /// undoing this migration.
    /// </remarks>
    public static async Task<string> BackUpAsync(string registryPath, SqliteConnection registry, CancellationToken ct)
    {
        var full = Path.GetFullPath(registryPath);
        var dir = Path.GetDirectoryName(full) ?? ".";
        var name = Path.GetFileNameWithoutExtension(full);

        var backup = Path.Combine(dir, $"{name}.pre-{Version}.db");
        if (File.Exists(backup))
        {
            backup = Path.Combine(dir,
                $"{name}.pre-{Version}-{DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}.db");
        }

        await using var vacuum = registry.CreateCommand();
        vacuum.CommandText = "VACUUM INTO $path";
        vacuum.Parameters.AddWithValue("$path", backup);
        await vacuum.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return backup;
    }

    private static async Task<long> CountAsync(
        SqliteConnection db, SqliteTransaction transaction, string table, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT COUNT(*) FROM {table}";
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);
    }

    private static async Task<List<string>> ColumnsAsync(SqliteConnection db, string schema, string table, CancellationToken ct)
    {
        var columns = new List<string>();
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}', '{schema}') ORDER BY cid";
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { columns.Add(reader.GetString(0)); }
        return columns;
    }

    private static async Task ExecuteAsync(SqliteConnection db, string sql, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
