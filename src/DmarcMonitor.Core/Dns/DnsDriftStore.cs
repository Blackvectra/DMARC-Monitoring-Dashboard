using System.Globalization;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>One change seen in a domain's records between two scans.</summary>
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

    /// <summary>True when this product changed the domain's DNS itself in the two days before.</summary>
    public bool WasExpected { get; init; }

    /// <summary>When somebody first looked at it - through the finding it belongs to, or, for a change from before findings existed, the row's own mark.</summary>
    public DateTimeOffset? AcknowledgedAt { get; init; }
    public string? AcknowledgedBy { get; init; }
    public string? Note { get; init; }

    public bool IsAcknowledged => AcknowledgedAt is not null;

    public string DomainId { get; init; } = "";

    /// <summary>The finding this change raised or moved: the one with the same domain and record.</summary>
    public string? FindingId { get; init; }
    public string? FindingSourceState { get; init; }
    public string? FindingAnalystState { get; init; }

    /// <summary>True when a later scan read the record as it was before the change.</summary>
    public bool IsResolved => string.Equals(FindingSourceState, SourceStates.Resolved, StringComparison.Ordinal);
}

/// <summary>
/// Reads DNS drift - what changed in a domain's records, and whether anybody
/// has looked at it yet - and records that somebody did.
/// </summary>
/// <remarks>
/// <para>
/// Written by <see cref="DnsSnapshotStore"/> as a scan finds each change;
/// this reads them back. Scoped the way every other read is: an organization
/// sees its own domains, and a customer login sees only its own client's.
/// </para>
/// <para>
/// Whether a change has been looked at is a fact about its finding, not about
/// the change: a domain's record has one finding however many nights it
/// drifts, and acknowledging a change acknowledges that. The acknowledgement
/// columns on the row itself are read for changes from before findings
/// existed and written for nothing newer.
/// </para>
/// </remarks>
public sealed class DnsDriftStore(string databasePath)
{
    /// <summary>The organization's database and each client's file; see ClientDatabases.</summary>
    private readonly ClientDatabases _files = new(databasePath);

    private readonly FindingLifecycle _lifecycle = new(databasePath);

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
                   e.summary, e.severity, e.was_expected,
                   COALESCE(e.acknowledged_at, a.at), COALESCE(e.acknowledged_by, a.actor), COALESCE(e.acknowledgement_note, a.note),
                   e.domain_id, f.id, f.source_state, f.analyst_state
            FROM dns_drift_events e
            JOIN domains d ON d.id = e.domain_id
            LEFT JOIN clients c ON c.id = e.client_id
            LEFT JOIN main.findings f
                   ON f.domain_id = e.domain_id AND f.source_id = 'dns-scan'
                  AND f.dedup_key = 'dns:' || e.domain_id || ':' || e.record_type
            LEFT JOIN main.finding_events a
                   ON a.id = (SELECT x.id FROM main.finding_events x
                              WHERE x.finding_id = f.id
                                AND x.kind IN ('Acknowledged', 'AnalystStateChanged', 'ExceptionApplied')
                              ORDER BY x.at DESC, x.rowid DESC LIMIT 1)
            WHERE ($tenant IS NULL OR e.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
              AND ($domain IS NULL OR d.name = $domain)
              AND ($open = 0 OR (e.acknowledged_at IS NULL AND (f.id IS NULL OR f.analyst_state = 'unreviewed')))
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
                DomainId = reader.GetString(13),
                FindingId = Text(14),
                FindingSourceState = Text(15),
                FindingAnalystState = Text(16),
            });
        }

        return events;
    }

    /// <summary>
    /// Records that somebody has seen a change, by acknowledging the finding
    /// it belongs to. Returns false when there is no such change in the
    /// caller's organization, or somebody already has.
    /// </summary>
    public async Task<bool> AcknowledgeAsync(
        string id, string by, string? note, string? tenantId, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(by);

        // The change is in whichever client's file its domain is; each file
        // in the caller's scope is asked in turn, and the first to hold it
        // answers with what identifies its finding.
        (string Tenant, string Client, string Domain, string Record, bool MarkedOnRow)? change = null;
        await _files.FirstAsync(ClientScope.For(tenantId, clientSlug), write: false, async (db, _, token) =>
        {
            await using var command = db.CreateCommand();
            command.CommandText = """
                SELECT tenant_id, client_id, domain_id, record_type, acknowledged_at IS NOT NULL
                FROM dns_drift_events
                WHERE id = $id
                  AND ($tenant IS NULL OR tenant_id = $tenant)
                  AND ($client IS NULL OR client_id = (SELECT id FROM clients WHERE slug = $client AND tenant_id = dns_drift_events.tenant_id))
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
            command.Parameters.AddWithValue("$client", (object?)clientSlug ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            if (!await reader.ReadAsync(token).ConfigureAwait(false)) { return false; }
            change = (reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4) == 1);
            return true;
        }, ct).ConfigureAwait(false);

        if (change is not { } found) { return false; }

        var finding = await _lifecycle.Store.FindAsync(
            found.Tenant, FindingSourceIds.DnsScan, found.Client, DnsFindingSource.DedupKey(found.Domain, found.Record), ct).ConfigureAwait(false);
        if (finding is not null)
        {
            if (!string.Equals(finding.AnalystState, AnalystStates.Unreviewed, StringComparison.Ordinal)) { return false; }
            return await _lifecycle.AcknowledgeAsync(finding.Id, by, note, tenantId, clientSlug, ct).ConfigureAwait(false) is not null;
        }

        // A change from before findings existed keeps its own mark.
        if (found.MarkedOnRow) { return false; }
        return await _files.FirstAsync(ClientScope.For(tenantId, clientSlug), write: true, async (db, _, token) =>
        {
            await using var command = db.CreateCommand();
            command.CommandText = """
                UPDATE dns_drift_events
                SET acknowledged_at = $at, acknowledged_by = $by, acknowledgement_note = $note
                WHERE id = $id AND acknowledged_at IS NULL
                """;
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$by", by.Trim());
            command.Parameters.AddWithValue("$note", string.IsNullOrWhiteSpace(note) ? DBNull.Value : note.Trim());
            command.Parameters.AddWithValue("$id", id);
            return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) == 1;
        }, ct).ConfigureAwait(false);
    }

    private static DateTimeOffset? Parse(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value)
            ? value
            : null;
}
