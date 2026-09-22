using System.Globalization;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// The organizations, read and written.
/// </summary>
/// <remarks>
/// Writes here are setup, like onboarding a client: naming an organization,
/// saying which groups belong to it, and how it looks. Nothing here touches
/// report data.
/// </remarks>
public sealed class OrganizationStore(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
    }.ToString();

    private const string Select = """
        SELECT t.id, t.name, t.slug, t.entra_group_id,
               (SELECT COUNT(*) FROM clients c WHERE c.tenant_id = t.id AND c.deleted_at IS NULL AND c.slug <> 'unassigned'),
               (SELECT COUNT(*) FROM domains d WHERE d.tenant_id = t.id AND d.deleted_at IS NULL),
               t.admin_group_id, t.viewer_group_id,
               t.brand_primary_color, t.brand_logo, t.provider_name, t.brand_contact_block,
               t.engineer_group_id
        FROM tenants t
        WHERE t.deleted_at IS NULL
        """;

    /// <summary>Every organization, by name.</summary>
    public async Task<IReadOnlyList<Organization>> ListAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = Select + " ORDER BY t.name";

        var result = new List<Organization>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { result.Add(Row(reader)); }
        return result;
    }

    public async Task<Organization?> GetAsync(string slug, CancellationToken ct = default)
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

    /// <summary>Every client with a login group of its own, across organizations.</summary>
    public async Task<IReadOnlyList<ClientGroup>> ClientGroupsAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT t.slug, c.slug, c.name, c.entra_group_id
            FROM clients c JOIN tenants t ON t.id = c.tenant_id
            WHERE c.entra_group_id IS NOT NULL AND c.entra_group_id <> '' AND c.deleted_at IS NULL
            ORDER BY t.slug, c.slug
            """;

        var result = new List<ClientGroup>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add(new ClientGroup(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        return result;
    }

    /// <summary>
    /// Creates an organization. Returns it, or null when the slug is taken.
    /// </summary>
    public async Task<Organization?> CreateAsync(
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

        return new Organization(id, name.Trim(), wanted, Clean(entraGroupId), 0, 0);
    }

    /// <summary>Records which group does the day-to-day work here. Null clears it.</summary>
    public Task<bool> SetGroupAsync(string slug, string? entraGroupId, CancellationToken ct = default) =>
        SetGroupAsync(slug, OrganizationRole.Tech, entraGroupId, ct);

    /// <summary>Records which group holds a role in an organization. Null clears it.</summary>
    public Task<bool> SetGroupAsync(string slug, OrganizationRole role, string? entraGroupId, CancellationToken ct = default)
    {
        var column = role switch
        {
            OrganizationRole.Admin => "admin_group_id",
            OrganizationRole.Engineer => "engineer_group_id",
            // Not "tech_group_id". This column has held the working group
            // since the first release and every install's configuration
            // points at it; renaming it would be a migration that changes
            // nothing except the word.
            OrganizationRole.Tech => "entra_group_id",
            OrganizationRole.Viewer => "viewer_group_id",
            _ => throw new ArgumentOutOfRangeException(
                nameof(role), role, "A group holds the viewer, tech, engineer or admin role."),
        };
        return UpdateAsync(slug, $"{column} = $value", (object?)Clean(entraGroupId) ?? DBNull.Value, ct);
    }

    public Task<bool> RenameAsync(string slug, string name, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return UpdateAsync(slug, "name = $value", name.Trim(), ct);
    }

    /// <summary>
    /// Sets how an organization looks. Refuses a color that is not a plain
    /// hex or a logo that is not a small image, because both land in markup.
    /// </summary>
    public async Task<bool> SetBrandAsync(string slug, OrganizationBrand brand, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);
        ArgumentNullException.ThrowIfNull(brand);

        if (!OrganizationBrand.IsValidColor(Clean(brand.PrimaryColor)))
        {
            throw new ArgumentException("The color must be a six-digit hex such as #4f46e5.", nameof(brand));
        }
        if (!OrganizationBrand.IsValidLogo(Clean(brand.Logo)))
        {
            throw new ArgumentException($"The logo must be a PNG, JPEG, GIF, WebP or SVG image of at most {OrganizationBrand.MaxLogoLength / 1000} KB.", nameof(brand));
        }

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            UPDATE tenants
            SET brand_primary_color = $color, brand_logo = $logo, provider_name = $provider, brand_contact_block = $contact,
                updated_at = $now
            WHERE slug = $slug AND deleted_at IS NULL
            """;
        command.Parameters.AddWithValue("$color", (object?)Clean(brand.PrimaryColor)?.ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$logo", (object?)Clean(brand.Logo) ?? DBNull.Value);
        command.Parameters.AddWithValue("$provider", (object?)Clean(brand.ProviderName) ?? DBNull.Value);
        command.Parameters.AddWithValue("$contact", (object?)Clean(brand.ContactBlock) ?? DBNull.Value);
        command.Parameters.AddWithValue("$now", Iso(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    private async Task<bool> UpdateAsync(string slug, string set, object value, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        // The SET clause is one of the literals above, never caller input.
        command.CommandText = $"UPDATE tenants SET {set}, updated_at = $now WHERE slug = $slug AND deleted_at IS NULL";
        command.Parameters.AddWithValue("$value", value);
        command.Parameters.AddWithValue("$now", Iso(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static Organization Row(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2),
        r.IsDBNull(3) ? null : r.GetString(3),
        r.GetInt32(4), r.GetInt32(5),
        r.IsDBNull(6) ? null : r.GetString(6),
        r.IsDBNull(7) ? null : r.GetString(7),
        r.IsDBNull(12) ? null : r.GetString(12),
        new OrganizationBrand(
            r.IsDBNull(8) ? null : r.GetString(8),
            r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10),
            r.IsDBNull(11) ? null : r.GetString(11)));

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
