using System.Globalization;
using System.Reflection;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>One migration: a version, what it is for, and the SQL.</summary>
public sealed record Migration(string Version, string Description, string Sql);

/// <summary>What bringing a database up to date did.</summary>
/// <param name="Split">What 0019 did, when this run was the one that split the database into client files.</param>
/// <param name="ClientFiles">Client files a client-schema migration changed.</param>
public sealed record MigrationResult(
    IReadOnlyList<string> Applied, string Version, SplitResult? Split = null, IReadOnlyList<string>? ClientFiles = null)
{
    public bool Changed => Applied.Count > 0 || ClientFiles is { Count: > 0 };
}

/// <summary>
/// Bringing an existing database up to the current schema.
///
/// schema.sql builds a new database and has always been complete, so a fresh
/// install was fine. An install that already had data was not: adding a table
/// to schema.sql did nothing to a database created before it, and the first
/// code to touch that table failed with "no such table" - which is how a
/// routine upgrade turns into an outage on somebody's server.
///
/// So every change to the schema after the baseline also lands here as a
/// numbered file, and these are applied in order to whatever the database
/// already has. The versions live in schema_migrations, which schema.sql has
/// populated from the beginning; this is the part that reads it.
/// </summary>
public static class DatabaseMigrations
{
    /// <summary>
    /// Everything schema.sql creates in one go, so a database it built is
    /// already at this version and needs nothing replayed into it.
    /// </summary>
    public const string BaselineVersion = "0019";

    /// <summary>
    /// The migrations, in order.
    /// </summary>
    /// <remarks>
    /// Compiled in rather than read from disk, for the same reason schema.sql
    /// is: a published binary has no checkout beside it, and an upgrade that
    /// only works from a source tree is not an upgrade.
    /// </remarks>
    public static IReadOnlyList<Migration> All { get; } = Load();

    /// <summary>
    /// Applies whatever this database has not had yet.
    /// </summary>
    /// <remarks>
    /// Each migration runs in its own transaction and records its version in
    /// the same one, so an interrupted upgrade leaves the database at a
    /// version it really is at, rather than at one it was half way to.
    /// </remarks>
    public static async Task<MigrationResult> ApplyAsync(string databasePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        SplitResult? split = null;
        var ran = new List<string>();
        string version;

        await using (var db = Open(databasePath))
        {
            await db.OpenAsync(ct).ConfigureAwait(false);

            var applied = await AppliedAsync(db, ct).ConfigureAwait(false);

            foreach (var migration in All)
            {
                ct.ThrowIfCancellationRequested();
                if (applied.Contains(migration.Version)) { continue; }

                // The split moves every client's rows into a file of its own
                // before its SQL drops them here. A copy of the database is
                // taken first, outside any transaction, as VACUUM INTO needs.
                var splitting = migration.Version == ClientFileSplit.Version;
                var backup = splitting
                    ? await ClientFileSplit.BackUpAsync(databasePath, db, ct).ConfigureAwait(false)
                    : null;

                // IMMEDIATE, so the split's reads and its drop are one moment
                // for every other writer: nothing can add a row between them.
                await using var transaction = db.BeginTransaction(deferred: false);

                if (splitting)
                {
                    split = await ClientFileSplit.RunAsync(databasePath, db, transaction, backup!, ct).ConfigureAwait(false);
                }

                await RunAsync(db, transaction, migration, ct).ConfigureAwait(false);
                await transaction.CommitAsync(ct).ConfigureAwait(false);
                ran.Add($"{migration.Version} {migration.Description}");
            }

            version = await VersionAsync(db, ct).ConfigureAwait(false);
        }

        if (split is not null)
        {
            // The tables the split dropped leave their pages free; giving them
            // back makes this file the few hundred kilobytes it now is rather
            // than the size it was. Worth trying, not worth failing over.
            try
            {
                await using var db = Open(databasePath);
                await db.OpenAsync(ct).ConfigureAwait(false);
                await using var vacuum = db.CreateCommand();
                vacuum.CommandText = "VACUUM";
                await vacuum.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            catch (SqliteException) { }
        }

        // Client files have their own series. Only once the database is split
        // is there anything to apply it to.
        IReadOnlyList<string> clientFiles = [];
        if (string.CompareOrdinal(version, ClientFileSplit.Version) >= 0)
        {
            clientFiles = await new ClientDatabases(databasePath).MigrateAllAsync(ct).ConfigureAwait(false);
        }

        return new MigrationResult(ran, version, split, clientFiles);
    }

    /// <summary>
    /// Applies whatever of <paramref name="migrations"/> this database has
    /// not had: the same bookkeeping, for a series other than the
    /// organization's - a client file's.
    /// </summary>
    internal static async Task<MigrationResult> ApplyAsync(
        string databasePath, IReadOnlyList<Migration> migrations, CancellationToken ct = default)
    {
        await using var db = Open(databasePath);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var applied = await AppliedAsync(db, ct).ConfigureAwait(false);
        var ran = new List<string>();

        foreach (var migration in migrations)
        {
            ct.ThrowIfCancellationRequested();
            if (applied.Contains(migration.Version)) { continue; }

            await using var transaction = (SqliteTransaction)await db.BeginTransactionAsync(ct).ConfigureAwait(false);
            await RunAsync(db, transaction, migration, ct).ConfigureAwait(false);
            await transaction.CommitAsync(ct).ConfigureAwait(false);
            ran.Add($"{migration.Version} {migration.Description}");
        }

        return new MigrationResult(ran, await VersionAsync(db, ct).ConfigureAwait(false));
    }

    /// <summary>One migration's SQL and the row recording it, in the caller's transaction.</summary>
    private static async Task RunAsync(
        SqliteConnection db, SqliteTransaction transaction, Migration migration, CancellationToken ct)
    {
        await using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = migration.Sql;
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await using var record = db.CreateCommand();
        record.Transaction = transaction;
        record.CommandText =
            "INSERT INTO schema_migrations (version, applied_at, description) VALUES ($v, $at, $d)";
        record.Parameters.AddWithValue("$v", migration.Version);
        record.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        record.Parameters.AddWithValue("$d", migration.Description);
        await record.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// A connection that is not pooled, so nothing keeps the file open once it
    /// is disposed: the split renames folders, and a backup is copied.
    /// </summary>
    private static SqliteConnection Open(string databasePath) =>
        new(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());

    /// <summary>What the database has, without changing anything.</summary>
    public static async Task<string> VersionAsync(string databasePath, CancellationToken ct = default)
    {
        await using var db = Open(databasePath);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return await VersionAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Migrations this database has not had, without applying them.</summary>
    public static async Task<IReadOnlyList<Migration>> PendingAsync(string databasePath, CancellationToken ct = default)
    {
        await using var db = Open(databasePath);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var applied = await AppliedAsync(db, ct).ConfigureAwait(false);
        return [.. All.Where(m => !applied.Contains(m.Version))];
    }

    private static async Task<HashSet<string>> AppliedAsync(SqliteConnection db, CancellationToken ct)
    {
        var applied = new HashSet<string>(StringComparer.Ordinal);

        await using var command = db.CreateCommand();
        command.CommandText =
            "SELECT version FROM schema_migrations WHERE EXISTS "
            + "(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')";

        try
        {
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { applied.Add(reader.GetString(0)); }
        }
        catch (SqliteException)
        {
            // No schema_migrations at all means this is not one of our
            // databases, or predates the table. Either way nothing here can
            // safely be replayed into it.
        }

        return applied;
    }

    private static async Task<string> VersionAsync(SqliteConnection db, CancellationToken ct)
    {
        var applied = await AppliedAsync(db, ct).ConfigureAwait(false);
        return applied.Count == 0 ? "none" : applied.Max(StringComparer.Ordinal)!;
    }

    private static List<Migration> Load()
    {
        var assembly = Assembly.GetExecutingAssembly();

        return [.. assembly
            .GetManifestResourceNames()
            .Where(name => name.StartsWith("migration.", StringComparison.Ordinal)
                        && name.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name => Read(assembly, name))];
    }

    private static Migration Read(Assembly assembly, string resourceName)
    {
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"{resourceName} is compiled in but could not be opened.");
        using var reader = new StreamReader(stream);

        // "migration.0009-mta-sts-policies.sql" -> "0009", "mta sts policies"
        var parts = resourceName["migration.".Length..].Replace(".sql", "", StringComparison.Ordinal).Split('-', 2);

        return new Migration(
            parts[0],
            parts.Length > 1 ? parts[1].Replace('-', ' ') : parts[0],
            reader.ReadToEnd());
    }
}
