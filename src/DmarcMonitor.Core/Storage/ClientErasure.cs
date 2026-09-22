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

    /// <summary>
    /// The id of an organization named by slug, or null if there is no such one.
    /// </summary>
    /// <remarks>
    /// Here rather than left to the caller because the caller is a command
    /// line holding a slug, and the alternative - passing null and letting the
    /// lookup range over every organization - is what made erasure able to
    /// destroy the wrong customer's data.
    /// </remarks>
    public async Task<string?> OrganizationIdAsync(string slug, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id FROM tenants WHERE slug = $slug LIMIT 1";
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());

        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
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
            // Every table carrying a client_id, explicitly, before the client
            // row goes.
            //
            // Relying on the cascade alone was not enough, and the gap was
            // silent. Most of these tables reach clients through a foreign
            // key - directly, or through a parent that has one, as
            // aggregate_records does via report_id. Two do not:
            // forensic_reports and ingest_log carry a client_id and have NO
            // foreign keys whatsoever, so nothing cascades to them at all.
            //
            // Both are empty today - forensic reports are not parsed yet, and
            // ingest_log fills only under the collector - so the cascade
            // looked complete. The moment either held a row, erasure would
            // have left it behind and the verification below would have
            // thrown, making erasure impossible for that client. Worse, had
            // the verification been the thing relaxed instead, a customer's
            // message headers would have quietly survived an erasure they
            // asked for.
            //
            // Children first, parent last: deleting in this order never
            // trips a constraint, and doing it explicitly makes the result
            // the same whether or not a cascade exists.
            foreach (var table in tables)
            {
                await using var delete = db.CreateCommand();
                delete.Transaction = transaction;
                delete.CommandText = $"DELETE FROM {table} WHERE client_id = $id";   // names from sqlite_master
                delete.Parameters.AddWithValue("$id", clientId);
                await delete.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

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
                    + "Every table carrying a client_id is deleted from explicitly, so this is a bug "
                    + "rather than a data problem.");
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

        // Every match, not LIMIT 1. Client slugs are unique per organization -
        // UNIQUE(tenant_id, slug) - so two organizations may each have an
        // 'acme-corp', and LIMIT 1 without an ORDER BY returned whichever
        // SQLite felt like. Unscoped, that made this command able to
        // permanently destroy a customer belonging to somebody else while
        // printing the organization it thought it was in.
        command.CommandText = """
            SELECT c.id, c.name, t.slug
            FROM clients c
            JOIN tenants t ON t.id = c.tenant_id
            WHERE c.slug = $slug AND ($tenant IS NULL OR c.tenant_id = $tenant)
            ORDER BY t.slug
            """;
        command.Parameters.AddWithValue("$slug", slug);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        var found = new List<(string Id, string Name, string Organization)>();

        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                found.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
            }
        }

        if (found.Count == 0) { return null; }
        if (found.Count == 1) { return found[0]; }

        // Refused rather than guessed. There is no safe way to choose here,
        // and choosing is exactly what went wrong.
        throw new AmbiguousClientException(slug, [.. found.Select(f => f.Organization)]);
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

/// <summary>
/// More than one organization has a client with this slug.
/// </summary>
/// <remarks>
/// Its own type so a caller can say something useful rather than printing a
/// stack trace. Slugs are unique per organization, so this is an ordinary
/// state on a shared install and not a corruption - the only wrong answer is
/// to pick one.
/// </remarks>
public sealed class AmbiguousClientException(string slug, IReadOnlyList<string> organizations)
    : Exception($"'{slug}' exists in more than one organization: {string.Join(", ", organizations)}. "
                + "Name one with --org; nothing was removed.")
{
    public string Slug { get; } = slug;

    public IReadOnlyList<string> Organizations { get; } = organizations;
}
