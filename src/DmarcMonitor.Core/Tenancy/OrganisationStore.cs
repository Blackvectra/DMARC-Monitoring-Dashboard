using System.Globalization;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// The organisations, read and written.
/// </summary>
/// <remarks>
/// Writes here are setup, like onboarding a client: naming an organisation
/// and saying which group belongs to it. Nothing here touches report data.
/// </remarks>
public sealed class OrganisationStore(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
    }.ToString();

    private const string Select = """
        SELECT t.id, t.name, t.slug, t.entra_group_id,
               (SELECT COUNT(*) FROM clients c WHERE c.tenant_id = t.id AND c.deleted_at IS NULL AND c.slug <> 'unassigned'),
               (SELECT COUNT(*) FROM domains d WHERE d.tenant_id = t.id AND d.deleted_at IS NULL)
        FROM tenants t
        WHERE t.deleted_at IS NULL
        """;

    /// <summary>Every organisation, by name.</summary>
    public async Task<IReadOnlyList<Organisation>> ListAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = Select + " ORDER BY t.name";

        var result = new List<Organisation>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { result.Add(Row(reader)); }
        return result;
    }

    public async Task<Organisation?> GetAsync(string slug, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = Select + " AND t.slug = $slug LIMIT 1";
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? Row(reader) : null;
    }

    /// <summary>
    /// Creates an organisation. Returns it, or null when the slug is taken.
    /// </summary>
    public async Task<Organisation?> CreateAsync(
        string name, string? slug = null, string? entraGroupId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var wanted = ReportStore.Slugify(string.IsNullOrWhiteSpace(slug) ? name : slug);
        if (wanted.Length == 0) { return null; }

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using (var exists = db.CreateCommand())
        {
            exists.CommandText = "SELECT 1 FROM tenants WHERE slug = $slug LIMIT 1";
            exists.Parameters.AddWithValue("$slug", wanted);
            if (await exists.ExecuteScalarAsync(ct).ConfigureAwait(false) is not null) { return null; }
        }

        var id = Guid.NewGuid().ToString("N");
        var now = Iso(DateTimeOffset.UtcNow);
        await using (var insert = db.CreateCommand())
        {
            insert.CommandText = """
                INSERT INTO tenants (id, name, slug, deployment_mode, status, secret_backend, entra_group_id, created_at, updated_at)
                VALUES ($id, $name, $slug, 'self_hosted', 'active', 'dpapi', $group, $now, $now)
                """;
            insert.Parameters.AddWithValue("$id", id);
            insert.Parameters.AddWithValue("$name", name.Trim());
            insert.Parameters.AddWithValue("$slug", wanted);
            insert.Parameters.AddWithValue("$group", (object?)Clean(entraGroupId) ?? DBNull.Value);
            insert.Parameters.AddWithValue("$now", now);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        return new Organisation(id, name.Trim(), wanted, Clean(entraGroupId), 0, 0);
    }

    /// <summary>Records which group belongs to an organisation. Null clears it.</summary>
    public Task<bool> SetGroupAsync(string slug, string? entraGroupId, CancellationToken ct = default) =>
        UpdateAsync(slug, "entra_group_id = $value", (object?)Clean(entraGroupId) ?? DBNull.Value, ct);

    public Task<bool> RenameAsync(string slug, string name, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return UpdateAsync(slug, "name = $value", name.Trim(), ct);
    }

    private async Task<bool> UpdateAsync(string slug, string set, object value, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        // The SET clause is one of the two literals above, never caller input.
        command.CommandText = $"UPDATE tenants SET {set}, updated_at = $now WHERE slug = $slug AND deleted_at IS NULL";
        command.Parameters.AddWithValue("$value", value);
        command.Parameters.AddWithValue("$now", Iso(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static Organisation Row(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2),
        r.IsDBNull(3) ? null : r.GetString(3),
        r.GetInt32(4), r.GetInt32(5));

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
