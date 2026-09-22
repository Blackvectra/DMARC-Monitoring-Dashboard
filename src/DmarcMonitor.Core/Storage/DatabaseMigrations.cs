using System.Globalization;
using System.Reflection;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>One migration: a version, what it is for, and the SQL.</summary>
public sealed record Migration(string Version, string Description, string Sql);

/// <summary>What bringing a database up to date did.</summary>
public sealed record MigrationResult(IReadOnlyList<string> Applied, string Version)
{
    public bool Changed => Applied.Count > 0;
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
    public const string BaselineVersion = "0016";

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

        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);

        var applied = await AppliedAsync(db, ct).ConfigureAwait(false);
        var ran = new List<string>();

        foreach (var migration in All)
        {
            ct.ThrowIfCancellationRequested();
            if (applied.Contains(migration.Version)) { continue; }

            await using var transaction = (SqliteTransaction)await db.BeginTransactionAsync(ct).ConfigureAwait(false);

            await using (var command = db.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = migration.Sql;
                await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await using (var record = db.CreateCommand())
            {
                record.Transaction = transaction;
                record.CommandText =
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES ($v, $at, $d)";
                record.Parameters.AddWithValue("$v", migration.Version);
                record.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime
                    .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                record.Parameters.AddWithValue("$d", migration.Description);
                await record.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await transaction.CommitAsync(ct).ConfigureAwait(false);
            ran.Add($"{migration.Version} {migration.Description}");
        }

        return new MigrationResult(ran, await VersionAsync(db, ct).ConfigureAwait(false));
    }

    /// <summary>What the database has, without changing anything.</summary>
    public static async Task<string> VersionAsync(string databasePath, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);
        return await VersionAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Migrations this database has not had, without applying them.</summary>
    public static async Task<IReadOnlyList<Migration>> PendingAsync(string databasePath, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
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
            .Where(name => name.StartsWith("migration.", StringComparison.Ordinal))
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
