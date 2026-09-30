using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// Finds the one domain a name means.
/// </summary>
/// <remarks>
/// <para>
/// A domain belongs to an organization, and the same name can be held by two
/// of them: an MSP that collects for a customer, and the customer's own MSP, on
/// one install. Looking a name up without an organization used to take
/// whichever row SQLite reached first, and the row it took decided which
/// client's file an audit entry went into and which organization's DNS
/// provider token a write was made with.
/// </para>
/// <para>
/// So a lookup either names its organization, or the name is held by exactly
/// one. A name held by several and given no organization is refused with
/// <see cref="AmbiguousOrganizationException"/>. One organization, which is
/// every install that has not added a second, never notices.
/// </para>
/// </remarks>
internal static class DomainDirectory
{
    internal readonly record struct Match(string TenantId, string ClientId, string DomainId);

    /// <param name="tenantId">The organization it must belong to, or null for "the only one that has it".</param>
    /// <returns>The domain, or null when there is none.</returns>
    /// <exception cref="AmbiguousOrganizationException">No organization was named and several hold the name.</exception>
    internal static async Task<Match?> FindAsync(SqliteConnection db, string name, string? tenantId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var wanted = Normalize(name);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.tenant_id, d.client_id, d.id, t.slug
            FROM domains d
            JOIN tenants t ON t.id = d.tenant_id
            WHERE d.name = $name AND d.deleted_at IS NULL
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
            ORDER BY t.slug, d.id
            LIMIT 20
            """;
        command.Parameters.AddWithValue("$name", wanted);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        Match? first = null;
        var organizations = new List<string>();

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var slug = reader.GetString(3);
            if (!organizations.Contains(slug, StringComparer.Ordinal)) { organizations.Add(slug); }
            first ??= new Match(reader.GetString(0), reader.GetString(1), reader.GetString(2));
        }

        if (organizations.Count > 1)
        {
            throw new AmbiguousOrganizationException("domain", wanted, organizations);
        }

        return first;
    }

    internal static string Normalize(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();
}
