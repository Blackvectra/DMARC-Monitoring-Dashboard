using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Findings;

/// <summary>What is known about whether an engine is doing its job.</summary>
public static class SourceHealth
{
    /// <summary>The last attempt succeeded, within the cadence.</summary>
    public const string Healthy = "healthy";

    /// <summary>The last attempt failed, but a recent one succeeded.</summary>
    public const string Degraded = "degraded";

    /// <summary>The last success is older than the cadence allows, and nothing has said why.</summary>
    public const string Stale = "stale";

    /// <summary>The last attempt failed, and no success is recent enough to lean on.</summary>
    public const string Failed = "failed";

    /// <summary>Never attempted. Silence is not health.</summary>
    public const string Unknown = "unknown";
}

/// <summary>One engine's record of running for one client, or for the organization.</summary>
public sealed record FindingSource
{
    /// <summary>How much later than its cadence a source may run before it is stale.</summary>
    public const double Grace = 1.5;

    public required string Id { get; init; }
    public required string TenantId { get; init; }
    public string? ClientId { get; init; }
    public required string Kind { get; init; }
    public required int ExpectedEveryHours { get; init; }
    public DateTimeOffset? LastAttemptAt { get; init; }
    public DateTimeOffset? LastSuccessAt { get; init; }
    public DateTimeOffset? LastFailureAt { get; init; }
    public string? LastError { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }

    public string ClientSlug { get; init; } = "";
    public string ClientName { get; init; } = "";

    /// <summary>Judged when asked, against the clock, so a source that stopped shows as stale rather than as it last was.</summary>
    public string HealthAt(DateTimeOffset now)
    {
        if (LastAttemptAt is null) { return SourceHealth.Unknown; }

        var allowed = TimeSpan.FromHours(ExpectedEveryHours * Grace);
        var recentSuccess = LastSuccessAt is { } success && now - success <= allowed;

        // A success clears the error and a failure always writes one, so the
        // error says which the last attempt was even when both happened in
        // the same second.
        var lastFailed = LastError is not null;

        if (lastFailed) { return recentSuccess ? SourceHealth.Degraded : SourceHealth.Failed; }
        return recentSuccess ? SourceHealth.Healthy : SourceHealth.Stale;
    }
}

/// <summary>
/// Every engine that raises findings registers each run here, per client:
/// attempted, succeeded or failed, and how often it is expected. The
/// data-source health the operations page shows is judged from these rows,
/// and a source nobody has heard from is unknown, never healthy.
/// </summary>
public sealed class FindingSourceRegistry(string databasePath, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
        Pooling = false,
    }.ToString();

    public static string IdFor(string kind, string tenantId, string? clientId) =>
        clientId is null ? kind + ":" + tenantId : kind + ":" + clientId;

    /// <summary>
    /// Records one run of a source for one client, or for the organization
    /// when the client is null. A failure always carries an error, so the
    /// row can say which way the last attempt went.
    /// </summary>
    public async Task RecordAsync(
        string tenantId, string? clientId, string kind, bool succeeded, string? error, int expectedEveryHours,
        DateTimeOffset? at = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(expectedEveryHours, 0);

        var when = FindingStore.Stamp(at ?? _clock.GetUtcNow());
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO finding_sources
                (id, tenant_id, client_id, kind, expected_every_hours, last_attempt_at, last_success_at, last_failure_at, last_error, updated_at)
            VALUES ($id, $tenant, $client, $kind, $every, $now, $success, $failure, $error, $now)
            ON CONFLICT (id) DO UPDATE SET
                expected_every_hours = excluded.expected_every_hours,
                last_attempt_at = excluded.last_attempt_at,
                last_success_at = COALESCE(excluded.last_success_at, last_success_at),
                last_failure_at = COALESCE(excluded.last_failure_at, last_failure_at),
                last_error = CASE WHEN excluded.last_failure_at IS NULL THEN NULL ELSE excluded.last_error END,
                updated_at = excluded.updated_at
            """;
        command.Parameters.AddWithValue("$id", IdFor(kind, tenantId, clientId));
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$client", (object?)clientId ?? DBNull.Value);
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$every", expectedEveryHours);
        command.Parameters.AddWithValue("$now", when);
        command.Parameters.AddWithValue("$success", succeeded ? when : DBNull.Value);
        command.Parameters.AddWithValue("$failure", succeeded ? DBNull.Value : when);
        command.Parameters.AddWithValue("$error", succeeded ? DBNull.Value : string.IsNullOrWhiteSpace(error) ? "failed, and no reason was given" : error.Trim());
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>An organization's sources, or every organization's for null.</summary>
    public async Task<IReadOnlyList<FindingSource>> ListAsync(string? tenantId, string? clientSlug = null, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT s.id, s.tenant_id, s.client_id, s.kind, s.expected_every_hours, s.last_attempt_at, s.last_success_at,
                   s.last_failure_at, s.last_error, s.updated_at, COALESCE(c.slug, ''), COALESCE(c.name, '')
            FROM finding_sources s
            LEFT JOIN clients c ON c.id = s.client_id
            WHERE ($tenant IS NULL OR s.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
            ORDER BY s.kind, c.name, s.id
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)clientSlug?.Trim().ToLowerInvariant() ?? DBNull.Value);

        var sources = new List<FindingSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);

            sources.Add(new FindingSource
            {
                Id = reader.GetString(0),
                TenantId = reader.GetString(1),
                ClientId = Text(2),
                Kind = reader.GetString(3),
                ExpectedEveryHours = reader.GetInt32(4),
                LastAttemptAt = Text(5) is { } a ? FindingStore.Parse(a) : null,
                LastSuccessAt = Text(6) is { } s ? FindingStore.Parse(s) : null,
                LastFailureAt = Text(7) is { } f ? FindingStore.Parse(f) : null,
                LastError = Text(8),
                UpdatedAt = FindingStore.Parse(reader.GetString(9)),
                ClientSlug = reader.GetString(10),
                ClientName = reader.GetString(11),
            });
        }
        return sources;
    }

    /// <summary>The sources with their health as of now, for a page or a check.</summary>
    public async Task<IReadOnlyList<(FindingSource Source, string Health)>> HealthAsync(
        string? tenantId, string? clientSlug = null, CancellationToken ct = default)
    {
        var now = _clock.GetUtcNow();
        var sources = await ListAsync(tenantId, clientSlug, ct).ConfigureAwait(false);
        return [.. sources.Select(s => (s, s.HealthAt(now)))];
    }

    internal static string Describe(FindingSource source, DateTimeOffset now) =>
        source.Kind + (source.ClientName.Length > 0 ? " for " + source.ClientName : "") + ": " + source.HealthAt(now)
        + (source.LastSuccessAt is { } ok ? ", last success " + ok.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : ", never succeeded")
        + (source.LastError is { } error ? " (" + error + ")" : "");
}
