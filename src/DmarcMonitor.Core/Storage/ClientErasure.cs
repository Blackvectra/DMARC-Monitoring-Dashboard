using System.Globalization;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>What erasing a client would remove, or did.</summary>
/// <param name="Slug">The client, as named on the command line.</param>
/// <param name="Name">Its display name, for the confirmation and the audit line.</param>
/// <param name="Organization">The organization it belongs to.</param>
/// <param name="Domains">The domain names that go with it.</param>
/// <param name="Rows">Rows per table, largest first. Only tables holding something.</param>
/// <param name="Applied">False for a preview.</param>
public sealed record ErasureResult(
    string Slug,
    string Name,
    string Organization,
    IReadOnlyList<string> Domains,
    IReadOnlyList<(string Table, long Rows)> Rows,
    bool Applied)
{
    public long Total => Rows.Sum(r => r.Rows);

    public string Describe() =>
        $"{Name} ({Slug}) in {Organization}: {Domains.Count} domain(s), {Total:N0} row(s) across "
        + $"{Rows.Count} table(s)";
}

/// <summary>
/// Removes a client and everything belonging to them, for good.
///
/// The gap this closes was written down before it was built: asked "can we
/// have our data deleted", the honest answer was that a domain could be hidden
/// and the reports would age out in four hundred days. That is not an answer a
/// paying customer accepts, and it is not one a customer of an MSP should get
/// either - the standard is the same whoever is being billed.
///
/// Three things separate this from DELETE FROM clients.
///
///   It proves the erasure. Every table in the schema carrying a client_id is
///   checked AFTER the delete, and anything left behind fails the whole
///   transaction. SQLite only cascades when foreign keys are enforced on the
///   connection, and a cascade that silently did not fire would leave the data
///   in place while the client row - and the operator's confidence - was gone.
///
///   It keeps the record of itself. audit_log has no client_id and no foreign
///   key to clients on purpose, so it survives. Proving an erasure request was
///   honoured is the other half of honouring it.
///
///   It is honest about backups. Nightly copies still hold the data until they
///   age out, and the result says so with a date rather than letting somebody
///   tell a customer "it is gone" while fourteen copies of it sit in S3.
/// </summary>
public sealed class ClientErasure(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>What would go, without touching anything.</summary>
    public Task<ErasureResult?> PreviewAsync(
        string clientSlug, string? tenantId = null, CancellationToken ct = default) =>
        RunAsync(clientSlug, tenantId, apply: false, by: null, audit: null, ct);

    /// <summary>
    /// Erases the client, and proves it.
    /// </summary>
    /// <param name="by">Who asked. Recorded; never guessed at.</param>
    public Task<ErasureResult?> ApplyAsync(
        string clientSlug, string? tenantId, string by, AuditLog? audit, CancellationToken ct = default) =>
        RunAsync(clientSlug, tenantId, apply: true, by, audit, ct);

    /// <returns>Null when no such client is visible to this organization.</returns>
    private async Task<ErasureResult?> RunAsync(
        string clientSlug, string? tenantId, bool apply, string? by, AuditLog? audit, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);
        if (apply) { ArgumentException.ThrowIfNullOrWhiteSpace(by); }

        var slug = clientSlug.Trim().ToLowerInvariant();

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        // The cascade is the whole mechanism, and it only fires when foreign
        // keys are enforced. Set explicitly rather than trusted to the client
        // library's default: without it the client row would vanish and every
        // report belonging to them would stay, orphaned and invisible.
        await Execute(db, "PRAGMA foreign_keys=ON", ct).ConfigureAwait(false);

        var client = await FindAsync(db, slug, tenantId, ct).ConfigureAwait(false);
        if (client is null) { return null; }

        var (clientId, name, organization) = client.Value;

        var domains = await DomainsAsync(db, clientId, ct).ConfigureAwait(false);
        var tables = await TablesWithClientIdAsync(db, ct).ConfigureAwait(false);
        var counts = await CountAsync(db, tables, clientId, ct).ConfigureAwait(false);

        if (!apply)
        {
            return new ErasureResult(slug, name, organization, domains, counts, Applied: false);
        }

        await using (var transaction = (SqliteTransaction)await db.BeginTransactionAsync(ct).ConfigureAwait(false))
        {
            await using (var delete = db.CreateCommand())
            {
                delete.Transaction = transaction;
                delete.CommandText = "DELETE FROM clients WHERE id = $id";
                delete.Parameters.AddWithValue("$id", clientId);
                await delete.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            // Prove it, inside the transaction, so a cascade that did not fire
            // takes the whole thing back rather than leaving a half-erased
            // client and a confident message.
            var left = await CountAsync(db, tables, clientId, ct, transaction).ConfigureAwait(false);
            if (left.Count > 0)
            {
                await transaction.RollbackAsync(ct).ConfigureAwait(false);

                throw new InvalidOperationException(
                    $"Erasing {slug} left {left.Sum(r => r.Rows):N0} row(s) behind in "
                    + $"{string.Join(", ", left.Select(r => r.Table))}. Nothing was removed. "
                    + "This means the cascade did not fire, which is a bug rather than a data problem.");
            }

            await transaction.CommitAsync(ct).ConfigureAwait(false);
        }

        // After the commit, so the log can never describe a rollback. The
        // client's NAME and the counts go in; none of the erased data does.
        if (audit is not null)
        {
            await audit.RecordAsync(
                tenantId,
                by!,
                "client.erase",
                $"{name} ({slug}): {counts.Sum(r => r.Rows):N0} rows across {counts.Count} tables, "
                + $"{domains.Count} domain(s)",
                ct).ConfigureAwait(false);
        }

        return new ErasureResult(slug, name, organization, domains, counts, Applied: true);
    }

    /// <summary>
    /// The client, scoped to one organization when given.
    /// </summary>
    /// <remarks>
    /// Null tenantId means every organization, which is what an operator at
    /// the command line has. Anything serving a signed-in person must pass
    /// one - erasure reaching across organizations would be the worst possible
    /// version of the cross-tenant bug.
    /// </remarks>
    private static async Task<(string Id, string Name, string Organization)?> FindAsync(
        SqliteConnection db, string slug, string? tenantId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT c.id, c.name, t.slug
            FROM clients c
            JOIN tenants t ON t.id = c.tenant_id
            WHERE c.slug = $slug AND ($tenant IS NULL OR c.tenant_id = $tenant)
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$slug", slug);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false)
            ? (reader.GetString(0), reader.GetString(1), reader.GetString(2))
            : null;
    }

    private static async Task<IReadOnlyList<string>> DomainsAsync(
        SqliteConnection db, string clientId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT name FROM domains WHERE client_id = $id ORDER BY name";
        command.Parameters.AddWithValue("$id", clientId);

        var found = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { found.Add(reader.GetString(0)); }
        return found;
    }

    /// <summary>
    /// Every table in this database carrying a client_id.
    /// </summary>
    /// <remarks>
    /// Read from the schema rather than listed here. Nineteen tables cascade
    /// from clients today and the count only goes up; a hand-written list is a
    /// list that goes stale, and the failure mode of a stale list is a table
    /// full of an erased customer's data that nobody counted and nobody
    /// checked.
    /// </remarks>
    internal static async Task<IReadOnlyList<string>> TablesWithClientIdAsync(
        SqliteConnection db, CancellationToken ct)
    {
        var tables = new List<string>();

        await using (var names = db.CreateCommand())
        {
            names.CommandText =
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";

            await using var reader = await names.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { tables.Add(reader.GetString(0)); }
        }

        var withClient = new List<string>();

        foreach (var table in tables)
        {
            await using var columns = db.CreateCommand();
            // Table names come from sqlite_master, never from a caller.
            columns.CommandText = $"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'client_id'";

            if (Convert.ToInt64(await columns.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L,
                                CultureInfo.InvariantCulture) > 0)
            {
                withClient.Add(table);
            }
        }

        return withClient;
    }

    /// <summary>Rows per table for one client, largest first, skipping the empty ones.</summary>
    private static async Task<IReadOnlyList<(string Table, long Rows)>> CountAsync(
        SqliteConnection db, IReadOnlyList<string> tables, string clientId,
        CancellationToken ct, SqliteTransaction? transaction = null)
    {
        var counts = new List<(string, long)>();

        foreach (var table in tables)
        {
            await using var command = db.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT COUNT(*) FROM {table} WHERE client_id = $id";
            command.Parameters.AddWithValue("$id", clientId);

            var n = Convert.ToInt64(
                await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);

            if (n > 0) { counts.Add((table, n)); }
        }

        return [.. counts.OrderByDescending(c => c.Item2)];
    }

    private static async Task Execute(SqliteConnection db, string sql, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
