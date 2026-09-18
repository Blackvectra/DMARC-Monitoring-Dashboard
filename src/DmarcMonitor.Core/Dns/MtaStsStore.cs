using System.Globalization;
using System.Text.Json;
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
    public async Task<MtaStsPolicy?> GetAsync(string domain, CancellationToken ct = default)
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
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$name", domain.Trim().TrimEnd('.').ToLowerInvariant());

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        return new MtaStsPolicy
        {
            Mode = reader.GetString(0),
            Mx = JsonSerializer.Deserialize<string[]>(reader.GetString(1)) ?? [],
            MaxAgeSeconds = reader.GetInt32(2),
            Id = reader.GetString(3),
        };
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
    public async Task<MtaStsPolicy> SetAsync(
        string domain, string mode, IReadOnlyList<string> mx, string by,
        int maxAgeSeconds = MtaStsPolicy.DefaultMaxAgeSeconds, CancellationToken ct = default)
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

        var found = await IdsAsync(db, name, ct).ConfigureAwait(false);
        if (found is null)
        {
            throw new ArgumentException(
                $"{name} is not a domain in the database. Import its reports and file it under a client first.",
                nameof(domain));
        }

        var ids = found.Value;

        var existing = await GetAsync(name, ct).ConfigureAwait(false);
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

    public async Task<bool> RemoveAsync(string domain, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            DELETE FROM mta_sts_policies
            WHERE domain_id IN (SELECT id FROM domains WHERE name = $name)
            """;
        command.Parameters.AddWithValue("$name", domain.Trim().TrimEnd('.').ToLowerInvariant());

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

    private static async Task<(string TenantId, string ClientId, string DomainId)?> IdsAsync(
        SqliteConnection db, string domain, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText =
            "SELECT tenant_id, client_id, id FROM domains WHERE name = $name AND deleted_at IS NULL LIMIT 1";
        command.Parameters.AddWithValue("$name", domain);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        return (reader.GetString(0), reader.GetString(1), reader.GetString(2));
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
