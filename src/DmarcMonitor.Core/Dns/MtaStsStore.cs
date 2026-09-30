using System.Globalization;
using System.Text.Json;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>
/// The MTA-STS policies this product serves.
///
/// One per domain, fetched by the web app when a sender asks
/// mta-sts.&lt;domain&gt; for it. Stored rather than generated from live DNS on
/// each request, because a policy that changed whenever an MX answer changed
/// would quietly start refusing mail to a server somebody had just added -
/// and senders cache it for its max_age either way, so the change would
/// outlast whoever made it.
/// </summary>
public sealed class MtaStsStore(string databasePath)
{
    private readonly string _connectionString =
        new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();

    /// <summary>The policy to serve for a domain, or null when there is none.</summary>
    /// <param name="tenantId">
    /// The organization the domain belongs to. Null means "the only one that
    /// has a policy for it": when two organizations each hold a policy for the
    /// same name and none is named, the answer is none. The public endpoint
    /// cannot tell whose policy a sender means, and serving an arbitrary one
    /// is how a domain ends up publishing another organization's MX list in
    /// enforce mode.
    /// </param>
    public async Task<MtaStsPolicy?> GetAsync(string domain, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT p.mode, p.mx_json, p.max_age_seconds, p.policy_id
            FROM mta_sts_policies p
            JOIN domains d ON d.id = p.domain_id
            WHERE d.name = $name AND d.deleted_at IS NULL
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
            ORDER BY d.tenant_id, d.id
            LIMIT 2
            """;
        command.Parameters.AddWithValue("$name", DomainDirectory.Normalize(domain));
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        var policy = ReadPolicy(reader);

        // A second row with no organization named is a different
        // organization's policy for the same name.
        if (tenantId is null && await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        return policy;
    }

    private static MtaStsPolicy ReadPolicy(SqliteDataReader reader) => new()
    {
        Mode = reader.GetString(0),
        Mx = JsonSerializer.Deserialize<string[]>(reader.GetString(1)) ?? [],
        MaxAgeSeconds = reader.GetInt32(2),
        Id = reader.GetString(3),
    };

    private static async Task<MtaStsPolicy?> GetByDomainIdAsync(SqliteConnection db, string domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT mode, mx_json, max_age_seconds, policy_id FROM mta_sts_policies WHERE domain_id = $domain";
        command.Parameters.AddWithValue("$domain", domainId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? ReadPolicy(reader) : null;
    }

    /// <summary>
    /// Stores the policy for a domain, replacing whatever was there.
    /// </summary>
    /// <remarks>
    /// The id moves only when the policy really changed, because it is what
    /// tells senders to fetch the file again: one that moved on every save
    /// would have them re-fetching for nothing, and one that never moved
    /// would leave them on a policy that no longer exists.
    /// </remarks>
    /// <param name="tenantId">
    /// The organization the domain belongs to; null only when exactly one
    /// organization has it.
    /// </param>
    /// <exception cref="AmbiguousOrganizationException">Several organizations hold the domain and none was named.</exception>
    public async Task<MtaStsPolicy> SetAsync(
        string domain, string mode, IReadOnlyList<string> mx, string by,
        int maxAgeSeconds = MtaStsPolicy.DefaultMaxAgeSeconds, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(mode);
        ArgumentNullException.ThrowIfNull(mx);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var wanted = mode.Trim().ToLowerInvariant();

        if (wanted is not (MtaStsMode.Testing or MtaStsMode.Enforce or MtaStsMode.None))
        {
            throw new ArgumentException($"'{mode}' is not an MTA-STS mode. One of: testing, enforce, none.", nameof(mode));
        }

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var found = await DomainDirectory.FindAsync(db, name, tenantId, ct).ConfigureAwait(false);
        if (found is null)
        {
            throw new ArgumentException(
                $"{name} is not a domain in the database. Import its reports and file it under a client first.",
                nameof(domain));
        }

        var ids = found.Value;

        // This domain's own policy, by its id. Looked up by name it could be
        // another organization's, and "unchanged" would then keep a stranger's
        // policy id.
        var existing = await GetByDomainIdAsync(db, ids.DomainId, ct).ConfigureAwait(false);
        var mxJson = JsonSerializer.Serialize(mx);

        // Unchanged means unchanged, id included.
        if (existing is not null
            && string.Equals(existing.Mode, wanted, StringComparison.Ordinal)
            && existing.MaxAgeSeconds == maxAgeSeconds
            && string.Equals(JsonSerializer.Serialize(existing.Mx), mxJson, StringComparison.Ordinal))
        {
            return existing;
        }

        var policy = new MtaStsPolicy
        {
            Mode = wanted,
            Mx = mx,
            MaxAgeSeconds = maxAgeSeconds,
            Id = MtaStsPolicy.IdFor(DateTimeOffset.UtcNow),
        };

        var now = Iso(DateTimeOffset.UtcNow);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO mta_sts_policies
                (id, tenant_id, client_id, domain_id, mode, mx_json, max_age_seconds, policy_id,
                 created_at, updated_at, updated_by)
            VALUES ($id, $tenant, $client, $domain, $mode, $mx, $maxAge, $policyId, $now, $now, $by)
            ON CONFLICT(domain_id) DO UPDATE SET
                mode = $mode, mx_json = $mx, max_age_seconds = $maxAge, policy_id = $policyId,
                updated_at = $now, updated_by = $by
            """;
        command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue("$tenant", ids.TenantId);
        command.Parameters.AddWithValue("$client", ids.ClientId);
        command.Parameters.AddWithValue("$domain", ids.DomainId);
        command.Parameters.AddWithValue("$mode", policy.Mode);
        command.Parameters.AddWithValue("$mx", mxJson);
        command.Parameters.AddWithValue("$maxAge", policy.MaxAgeSeconds);
        command.Parameters.AddWithValue("$policyId", policy.Id);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$by", by);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return policy;
    }

    /// <param name="tenantId">The organization the domain belongs to; null only when exactly one organization has it.</param>
    /// <exception cref="AmbiguousOrganizationException">Several organizations hold the domain and none was named.</exception>
    public async Task<bool> RemoveAsync(string domain, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        // One domain's policy. By name alone this deleted the policy of every
        // organization that held the name.
        var found = await DomainDirectory.FindAsync(db, domain, tenantId, ct).ConfigureAwait(false);
        if (found is null) { return false; }

        await using var command = db.CreateCommand();
        command.CommandText = "DELETE FROM mta_sts_policies WHERE domain_id = $domain";
        command.Parameters.AddWithValue("$domain", found.Value.DomainId);

        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    /// <summary>Every domain with a policy, for the settings and fix pages.</summary>
    public async Task<IReadOnlyList<(string Domain, MtaStsPolicy Policy)>> ListAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.name, p.mode, p.mx_json, p.max_age_seconds, p.policy_id
            FROM mta_sts_policies p
            JOIN domains d ON d.id = p.domain_id
            WHERE d.deleted_at IS NULL
            ORDER BY d.name
            """;

        var result = new List<(string, MtaStsPolicy)>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add((reader.GetString(0), new MtaStsPolicy
            {
                Mode = reader.GetString(1),
                Mx = JsonSerializer.Deserialize<string[]>(reader.GetString(2)) ?? [],
                MaxAgeSeconds = reader.GetInt32(3),
                Id = reader.GetString(4),
            }));
        }

        return result;
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
