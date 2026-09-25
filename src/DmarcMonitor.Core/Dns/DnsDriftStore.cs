using System.Globalization;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>A change seen in a domain's DNS between two scans.</summary>
public sealed record DriftEvent
{
    public required string Id { get; init; }
    public required string Domain { get; init; }
    public string ClientName { get; init; } = "";
    public DateTimeOffset DetectedAt { get; init; }
    public required string RecordType { get; init; }
    public string? OldValue { get; init; }
    public string? NewValue { get; init; }
    public required string Summary { get; init; }
    public required string Severity { get; init; }

    /// <summary>True when this product changed the domain's DNS itself shortly before.</summary>
    public bool WasExpected { get; init; }

    public DateTimeOffset? AcknowledgedAt { get; init; }
    public string? AcknowledgedBy { get; init; }
    public string? Note { get; init; }

    public bool IsAcknowledged => AcknowledgedAt is not null;
}

/// <summary>
/// Reads and acknowledges DNS drift - what changed in a domain's records, and
/// whether anybody has looked at it yet.
/// </summary>
/// <remarks>
/// Written by <see cref="DnsSnapshotStore"/> as a scan finds each change;
/// this only reads them back and records that somebody saw one. Scoped the
/// way every other read is: an organization sees its own domains, and a
/// customer login sees only its own client's.
/// </remarks>
public sealed class DnsDriftStore(string databasePath)
{
    /// <summary>The organization's database and each client's file; see ClientDatabases.</summary>
    private readonly ClientDatabases _files = new(databasePath);

    /// <param name="tenantId">The organization, or null for every one (the master account).</param>
    /// <param name="clientSlug">Only this client's domains, for a customer login.</param>
    /// <param name="domain">Only this domain.</param>
    /// <param name="openOnly">Only changes nobody has acknowledged.</param>
    public async Task<IReadOnlyList<DriftEvent>> ListAsync(
        string? tenantId, string? clientSlug = null, string? domain = null, bool openOnly = false,
        int limit = 200, CancellationToken ct = default)
    {
        await using var db = await _files.OpenAsync(
            ClientScope.For(tenantId, clientSlug, domain), ["dns_drift_events"], ct: ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT e.id, d.name, COALESCE(c.name, ''), e.detected_at, e.record_type, e.old_value, e.new_value,
                   e.summary, e.severity, e.was_expected, e.acknowledged_at, e.acknowledged_by, e.acknowledgement_note
            FROM dns_drift_events e
            JOIN domains d ON d.id = e.domain_id
            LEFT JOIN clients c ON c.id = e.client_id
            WHERE ($tenant IS NULL OR e.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
              AND ($domain IS NULL OR d.name = $domain)
              AND ($open = 0 OR e.acknowledged_at IS NULL)
            ORDER BY e.detected_at DESC,
                     CASE e.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)clientSlug ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)domain?.Trim().TrimEnd('.').ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$open", openOnly ? 1 : 0);
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 2000));

        var events = new List<DriftEvent>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);

            events.Add(new DriftEvent
            {
                Id = reader.GetString(0),
                Domain = reader.GetString(1),
                ClientName = reader.GetString(2),
                DetectedAt = Parse(reader.GetString(3)) ?? DateTimeOffset.MinValue,
                RecordType = reader.GetString(4),
                OldValue = Text(5),
                NewValue = Text(6),
                Summary = reader.GetString(7),
                Severity = reader.GetString(8),
                WasExpected = reader.GetInt64(9) == 1,
                AcknowledgedAt = Text(10) is { } at ? Parse(at) : null,
                AcknowledgedBy = Text(11),
                Note = Text(12),
            });
        }

        return events;
    }

    /// <summary>
    /// Records that somebody has seen a change. Returns false when there is no
    /// such change in the caller's organization, or it was already acknowledged.
    /// </summary>
    public async Task<bool> AcknowledgeAsync(
        string id, string by, string? note, string? tenantId, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(by);

        // The event is in whichever client's file its domain is; each file in
        // the caller's scope is asked in turn, and the first to hold it
        // answers.
        return await _files.FirstAsync(ClientScope.For(tenantId, clientSlug), write: true, async (db, _, token) =>
        {
            await using var command = db.CreateCommand();
            command.CommandText = """
                UPDATE dns_drift_events
                SET acknowledged_at = $at, acknowledged_by = $by, acknowledgement_note = $note
                WHERE id = $id AND acknowledged_at IS NULL
                  AND ($tenant IS NULL OR tenant_id = $tenant)
                  AND ($client IS NULL OR client_id = (SELECT id FROM clients WHERE slug = $client AND tenant_id = dns_drift_events.tenant_id))
                """;
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$by", by.Trim());
            command.Parameters.AddWithValue("$note", string.IsNullOrWhiteSpace(note) ? DBNull.Value : note.Trim());
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
            command.Parameters.AddWithValue("$client", (object?)clientSlug ?? DBNull.Value);

            return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) == 1;
        }, ct).ConfigureAwait(false);
    }

    private static DateTimeOffset? Parse(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value)
            ? value
            : null;
}
