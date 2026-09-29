using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Findings;

/// <summary>Which findings a page or a command wants.</summary>
public sealed record FindingFilter
{
    /// <summary>The organization, or null for every one (the master account).</summary>
    public string? TenantId { get; init; }

    /// <summary>Only this client's, for a customer login.</summary>
    public string? ClientSlug { get; init; }
    public string? ClientId { get; init; }
    public string? DomainName { get; init; }
    public IReadOnlyList<string>? SourceStates { get; init; }
    public IReadOnlyList<string>? AnalystStates { get; init; }
    public IReadOnlyList<string>? Types { get; init; }
    public string? MinSeverity { get; init; }

    /// <summary>Only what wants a person: see <see cref="Finding.InQueue"/>.</summary>
    public bool InQueueOnly { get; init; }
    public bool ExceptedOnly { get; init; }
    public bool AwaitingVerificationOnly { get; init; }
    public DateTimeOffset? ObservedSince { get; init; }
    public int Limit { get; init; } = 500;
}

/// <summary>
/// Findings, their history, their exceptions: the tables in the
/// organization's database. The lifecycle decides what goes in them; this
/// only reads and writes.
/// </summary>
/// <remarks>
/// In the organization's database, not the client files, because a queue
/// over one file per client would be a union of every file on every page,
/// and because a finding is operational state about a client rather than
/// the client's data. Every row carries client_id, so erasing a client
/// covers these tables, and every read is scoped by organization.
/// </remarks>
public sealed class FindingStore(string databasePath)
{
    private const string Columns = """
        f.id, f.tenant_id, f.client_id, f.domain_id, f.source_id, f.type, f.rule, f.severity, f.title,
        f.dedup_key, f.evidence_ref, f.expected_ref, f.related_finding_id, f.source_state, f.analyst_state,
        f.remediation_stage, f.first_observed_at, f.last_observed_at, f.observation_count, f.absent_count,
        f.reopened_count, f.source_resolved_at, f.payload_json, f.created_at, f.updated_at,
        c.slug, c.name, d.name,
        x.id, x.reason, x.approver, x.compensating_control, x.approved_at, x.review_at, x.expires_at, x.created_by, x.created_at
        """;

    private const string From = """
        FROM findings f
        JOIN clients c ON c.id = f.client_id
        LEFT JOIN domains d ON d.id = f.domain_id
        LEFT JOIN finding_exceptions x ON x.finding_id = f.id AND x.ended_at IS NULL
        """;

    private static readonly IReadOnlyList<string> OpenStates = [SourceStates.Active, SourceStates.Unknown];

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
        Pooling = false,
    }.ToString();

    /// <summary>One finding, or null when there is none in the caller's scope.</summary>
    public async Task<Finding?> GetAsync(string id, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT {Columns} {From} WHERE f.id = $id AND ($tenant IS NULL OR f.tenant_id = $tenant) AND ($client IS NULL OR c.slug = $client)";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)clientSlug?.Trim().ToLowerInvariant() ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? Read(reader) : null;
    }

    /// <summary>The finding a source's observation belongs to, by its identity, or null.</summary>
    public async Task<Finding?> FindAsync(string tenantId, string sourceId, string clientId, string dedupKey, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT {Columns} {From} WHERE f.tenant_id = $tenant AND f.source_id = $source AND f.client_id = $client AND f.dedup_key = $key";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$source", sourceId);
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$key", dedupKey);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? Read(reader) : null;
    }

    /// <summary>
    /// The finding a source's key names, whichever organization it is in:
    /// for an engine following up something it raised itself, by an id only
    /// it made. Never for a page.
    /// </summary>
    public async Task<Finding?> FindBySourceKeyAsync(string sourceId, string dedupKey, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT {Columns} {From} WHERE f.source_id = $source AND f.dedup_key = $key";
        command.Parameters.AddWithValue("$source", sourceId);
        command.Parameters.AddWithValue("$key", dedupKey);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? Read(reader) : null;
    }

    /// <summary>Findings a source still has open in one scope: active or unknown, never resolved.</summary>
    public async Task<IReadOnlyList<Finding>> OpenForScopeAsync(
        string tenantId, string clientId, string sourceId, string? domainId = null, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns} {From}
            WHERE f.tenant_id = $tenant AND f.client_id = $client AND f.source_id = $source
              AND ($domain IS NULL OR f.domain_id = $domain)
              AND f.source_state IN ('active','unknown')
            ORDER BY f.first_observed_at, f.id
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$source", sourceId);
        command.Parameters.AddWithValue("$domain", (object?)domainId ?? DBNull.Value);
        return await ReadAllAsync(command, ct).ConfigureAwait(false);
    }

    /// <summary>Findings, worst and newest first.</summary>
    public async Task<IReadOnlyList<Finding>> ListAsync(FindingFilter filter, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(filter);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        var where = new List<string>
        {
            "($tenant IS NULL OR f.tenant_id = $tenant)",
            "($client IS NULL OR c.slug = $client)",
            "($clientId IS NULL OR f.client_id = $clientId)",
            "($domain IS NULL OR d.name = $domain)",
            "($since IS NULL OR f.last_observed_at >= $since)",
            "CASE f.severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END >= $min",
        };
        command.Parameters.AddWithValue("$tenant", (object?)filter.TenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)filter.ClientSlug?.Trim().ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$clientId", (object?)filter.ClientId ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)filter.DomainName?.Trim().TrimEnd('.').ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$since", filter.ObservedSince is { } since ? Stamp(since) : DBNull.Value);
        command.Parameters.AddWithValue("$min", Rank(filter.MinSeverity ?? "info"));

        if (filter.InQueueOnly)
        {
            where.Add("f.source_state <> 'resolved' AND f.analyst_state NOT IN ('closed','benign') AND x.id IS NULL");
        }
        if (filter.ExceptedOnly) { where.Add("x.id IS NOT NULL"); }
        if (filter.AwaitingVerificationOnly)
        {
            where.Add("f.remediation_stage IN ('dns_pending','dns_verified','effectiveness_pending')");
        }
        AddIn(command, where, "f.source_state", "ss", filter.SourceStates);
        AddIn(command, where, "f.analyst_state", "as", filter.AnalystStates);
        AddIn(command, where, "f.type", "ty", filter.Types);

        command.CommandText = $"""
            SELECT {Columns} {From}
            WHERE {string.Join(" AND ", where)}
            ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                     f.last_observed_at DESC, f.id
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(filter.Limit, 1, 5000));
        return await ReadAllAsync(command, ct).ConfigureAwait(false);
    }

    public async Task InsertAsync(Finding finding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO findings
                (id, tenant_id, client_id, domain_id, source_id, type, rule, severity, title, dedup_key,
                 evidence_ref, expected_ref, related_finding_id, source_state, analyst_state, remediation_stage,
                 first_observed_at, last_observed_at, observation_count, absent_count, reopened_count,
                 source_resolved_at, payload_json, created_at, updated_at)
            VALUES
                ($id, $tenant, $client, $domain, $source, $type, $rule, $severity, $title, $key,
                 $evidence, $expected, $related, $sourceState, $analystState, $stage,
                 $first, $last, $observations, $absent, $reopened,
                 $resolvedAt, $payload, $created, $updated)
            """;
        Bind(command, finding);
        command.Parameters.AddWithValue("$id", finding.Id);
        command.Parameters.AddWithValue("$tenant", finding.TenantId);
        command.Parameters.AddWithValue("$client", finding.ClientId);
        command.Parameters.AddWithValue("$domain", (object?)finding.DomainId ?? DBNull.Value);
        command.Parameters.AddWithValue("$source", finding.SourceId);
        command.Parameters.AddWithValue("$key", finding.DedupKey);
        command.Parameters.AddWithValue("$first", Stamp(finding.FirstObservedAt));
        command.Parameters.AddWithValue("$created", Stamp(finding.CreatedAt));
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Writes everything about a finding that can change after it exists.</summary>
    public async Task UpdateAsync(Finding finding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            UPDATE findings SET
                type = $type, rule = $rule, severity = $severity, title = $title,
                evidence_ref = $evidence, expected_ref = $expected, related_finding_id = $related,
                source_state = $sourceState, analyst_state = $analystState, remediation_stage = $stage,
                last_observed_at = $last, observation_count = $observations, absent_count = $absent,
                reopened_count = $reopened, source_resolved_at = $resolvedAt, payload_json = $payload,
                updated_at = $updated
            WHERE id = $id
            """;
        Bind(command, finding);
        command.Parameters.AddWithValue("$id", finding.Id);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static void Bind(SqliteCommand command, Finding f)
    {
        command.Parameters.AddWithValue("$type", f.Type);
        command.Parameters.AddWithValue("$rule", (object?)f.Rule ?? DBNull.Value);
        command.Parameters.AddWithValue("$severity", f.Severity);
        command.Parameters.AddWithValue("$title", f.Title);
        command.Parameters.AddWithValue("$evidence", (object?)f.EvidenceRef ?? DBNull.Value);
        command.Parameters.AddWithValue("$expected", (object?)f.ExpectedRef ?? DBNull.Value);
        command.Parameters.AddWithValue("$related", (object?)f.RelatedFindingId ?? DBNull.Value);
        command.Parameters.AddWithValue("$sourceState", f.SourceState);
        command.Parameters.AddWithValue("$analystState", f.AnalystState);
        command.Parameters.AddWithValue("$stage", (object?)f.RemediationStage ?? DBNull.Value);
        command.Parameters.AddWithValue("$last", Stamp(f.LastObservedAt));
        command.Parameters.AddWithValue("$observations", f.ObservationCount);
        command.Parameters.AddWithValue("$absent", f.AbsentCount);
        command.Parameters.AddWithValue("$reopened", f.ReopenedCount);
        command.Parameters.AddWithValue("$resolvedAt", f.SourceResolvedAt is { } at ? Stamp(at) : DBNull.Value);
        command.Parameters.AddWithValue("$payload", (object?)f.PayloadJson ?? DBNull.Value);
        command.Parameters.AddWithValue("$updated", Stamp(f.UpdatedAt));
    }

    // ---- history ---------------------------------------------------------------

    public async Task<FindingEvent> AppendEventAsync(
        Finding finding, string kind, string actor, DateTimeOffset at,
        string? fromValue = null, string? toValue = null, string? note = null, string? payloadJson = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        var entry = new FindingEvent
        {
            Id = Guid.NewGuid().ToString(),
            FindingId = finding.Id,
            At = at,
            Kind = kind,
            Actor = actor.Trim(),
            FromValue = fromValue,
            ToValue = toValue,
            Note = string.IsNullOrWhiteSpace(note) ? null : note.Trim(),
            PayloadJson = payloadJson,
        };

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO finding_events (id, finding_id, tenant_id, client_id, at, kind, actor, from_value, to_value, note, payload_json)
            VALUES ($id, $finding, $tenant, $client, $at, $kind, $actor, $from, $to, $note, $payload)
            """;
        command.Parameters.AddWithValue("$id", entry.Id);
        command.Parameters.AddWithValue("$finding", finding.Id);
        command.Parameters.AddWithValue("$tenant", finding.TenantId);
        command.Parameters.AddWithValue("$client", finding.ClientId);
        command.Parameters.AddWithValue("$at", Stamp(at));
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$actor", entry.Actor);
        command.Parameters.AddWithValue("$from", (object?)fromValue ?? DBNull.Value);
        command.Parameters.AddWithValue("$to", (object?)toValue ?? DBNull.Value);
        command.Parameters.AddWithValue("$note", (object?)entry.Note ?? DBNull.Value);
        command.Parameters.AddWithValue("$payload", (object?)payloadJson ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return entry;
    }

    /// <summary>A finding's history, oldest first.</summary>
    public async Task<IReadOnlyList<FindingEvent>> EventsAsync(string findingId, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT id, finding_id, at, kind, actor, from_value, to_value, note, payload_json
            FROM finding_events WHERE finding_id = $finding ORDER BY at, rowid
            """;
        command.Parameters.AddWithValue("$finding", findingId);

        var events = new List<FindingEvent>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { events.Add(ReadEvent(reader, 0)); }
        return events;
    }

    /// <summary>
    /// What happened across an organization's findings since a moment, newest
    /// first: the "what changed" view, and what a destination is told about.
    /// </summary>
    public async Task<IReadOnlyList<FindingChange>> ChangesAsync(
        string? tenantId, DateTimeOffset since, IReadOnlyList<string>? kinds = null, string? clientSlug = null,
        int limit = 500, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        var where = new List<string>
        {
            "($tenant IS NULL OR e.tenant_id = $tenant)",
            "($client IS NULL OR c.slug = $client)",
            "e.at >= $since",
        };
        AddIn(command, where, "e.kind", "k", kinds);

        command.CommandText = $"""
            SELECT {Columns},
                   e.id, e.finding_id, e.at, e.kind, e.actor, e.from_value, e.to_value, e.note, e.payload_json
            FROM finding_events e
            JOIN findings f ON f.id = e.finding_id
            JOIN clients c ON c.id = f.client_id
            LEFT JOIN domains d ON d.id = f.domain_id
            LEFT JOIN finding_exceptions x ON x.finding_id = f.id AND x.ended_at IS NULL
            WHERE {string.Join(" AND ", where)}
            ORDER BY e.at DESC, e.rowid DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)clientSlug?.Trim().ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$since", Stamp(since));
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 5000));

        var changes = new List<FindingChange>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            changes.Add(new FindingChange(ReadEvent(reader, 37), Read(reader)));
        }
        return changes;
    }

    /// <summary>
    /// An organization's finding events a destination has not delivered,
    /// oldest first: those of the kinds given, since a moment, on findings
    /// at or above a severity rank (0 info, 1 warning, 2 critical).
    /// </summary>
    public async Task<IReadOnlyList<FindingChange>> UndeliveredAsync(
        string webhookId, string tenantId, DateTimeOffset since, IReadOnlyList<string> kinds, int minRank, int limit,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kinds);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        var where = new List<string>
        {
            "f.tenant_id = $tenant",
            "e.at >= $since",
            "CASE f.severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END >= $min",
            "w.delivered_at IS NULL",
        };
        AddIn(command, where, "e.kind", "k", kinds);

        command.CommandText = $"""
            SELECT {Columns},
                   e.id, e.finding_id, e.at, e.kind, e.actor, e.from_value, e.to_value, e.note, e.payload_json
            FROM finding_events e
            JOIN findings f ON f.id = e.finding_id
            JOIN clients c ON c.id = f.client_id
            LEFT JOIN domains d ON d.id = f.domain_id
            LEFT JOIN finding_exceptions x ON x.finding_id = f.id AND x.ended_at IS NULL
            LEFT JOIN webhook_deliveries w ON w.webhook_id = $webhook AND w.event_id = e.id
            WHERE {string.Join(" AND ", where)}
            ORDER BY e.at, e.rowid
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$webhook", webhookId);
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$since", Stamp(since));
        command.Parameters.AddWithValue("$min", minRank);
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 5000));

        var changes = new List<FindingChange>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            changes.Add(new FindingChange(ReadEvent(reader, 37), Read(reader)));
        }
        return changes;
    }

    // ---- exceptions -------------------------------------------------------------

    public async Task InsertExceptionAsync(FindingExceptionRecord exception, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(exception);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO finding_exceptions
                (id, tenant_id, client_id, finding_id, reason, approver, compensating_control,
                 approved_at, review_at, expires_at, created_by, created_at)
            VALUES ($id, $tenant, $client, $finding, $reason, $approver, $control, $approved, $review, $expires, $by, $created)
            """;
        command.Parameters.AddWithValue("$id", exception.Id);
        command.Parameters.AddWithValue("$tenant", exception.TenantId);
        command.Parameters.AddWithValue("$client", exception.ClientId);
        command.Parameters.AddWithValue("$finding", exception.FindingId);
        command.Parameters.AddWithValue("$reason", exception.Reason);
        command.Parameters.AddWithValue("$approver", exception.Approver);
        command.Parameters.AddWithValue("$control", exception.CompensatingControl);
        command.Parameters.AddWithValue("$approved", Stamp(exception.ApprovedAt));
        command.Parameters.AddWithValue("$review", Stamp(exception.ReviewAt));
        command.Parameters.AddWithValue("$expires", exception.ExpiresAt is { } expires ? Stamp(expires) : DBNull.Value);
        command.Parameters.AddWithValue("$by", exception.CreatedBy);
        command.Parameters.AddWithValue("$created", Stamp(exception.CreatedAt));
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Ends an open exception. Returns false when it was not open.</summary>
    public async Task<bool> EndExceptionAsync(string exceptionId, string reason, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "UPDATE finding_exceptions SET ended_at = $at, ended_reason = $reason WHERE id = $id AND ended_at IS NULL";
        command.Parameters.AddWithValue("$at", Stamp(at));
        command.Parameters.AddWithValue("$reason", reason);
        command.Parameters.AddWithValue("$id", exceptionId);
        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) == 1;
    }

    /// <summary>Open exceptions whose expiry has passed.</summary>
    public async Task<IReadOnlyList<FindingExceptionRecord>> ExpiredAsync(DateTimeOffset now, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT {ExceptionColumns} FROM finding_exceptions x WHERE x.ended_at IS NULL AND x.expires_at IS NOT NULL AND x.expires_at <= $now ORDER BY x.expires_at";
        command.Parameters.AddWithValue("$now", Stamp(now));

        var found = new List<FindingExceptionRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { found.Add(ReadException(reader, 0)!); }
        return found;
    }

    /// <summary>An organization's exceptions, open ones first and soonest review first.</summary>
    public async Task<IReadOnlyList<FindingExceptionRecord>> ExceptionsAsync(string? tenantId, bool openOnly = true, CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT {ExceptionColumns} FROM finding_exceptions x
            WHERE ($tenant IS NULL OR x.tenant_id = $tenant) AND ($open = 0 OR x.ended_at IS NULL)
            ORDER BY x.ended_at IS NOT NULL, x.review_at
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$open", openOnly ? 1 : 0);

        var found = new List<FindingExceptionRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { found.Add(ReadException(reader, 0)!); }
        return found;
    }

    private const string ExceptionColumns =
        "x.id, x.tenant_id, x.client_id, x.finding_id, x.reason, x.approver, x.compensating_control, x.approved_at, x.review_at, x.expires_at, x.ended_at, x.ended_reason, x.created_by, x.created_at";

    // ---- reading ---------------------------------------------------------------

    private static async Task<IReadOnlyList<Finding>> ReadAllAsync(SqliteCommand command, CancellationToken ct)
    {
        var found = new List<Finding>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { found.Add(Read(reader)); }
        return found;
    }

    private static Finding Read(SqliteDataReader r)
    {
        string? Text(int i) => r.IsDBNull(i) ? null : r.GetString(i);

        FindingExceptionRecord? open = r.IsDBNull(28) ? null : new FindingExceptionRecord
        {
            Id = r.GetString(28),
            TenantId = r.GetString(1),
            ClientId = r.GetString(2),
            FindingId = r.GetString(0),
            Reason = r.GetString(29),
            Approver = r.GetString(30),
            CompensatingControl = r.GetString(31),
            ApprovedAt = Parse(r.GetString(32)),
            ReviewAt = Parse(r.GetString(33)),
            ExpiresAt = Text(34) is { } e ? Parse(e) : null,
            CreatedBy = r.GetString(35),
            CreatedAt = Parse(r.GetString(36)),
        };

        return new Finding
        {
            Id = r.GetString(0),
            TenantId = r.GetString(1),
            ClientId = r.GetString(2),
            DomainId = Text(3),
            SourceId = r.GetString(4),
            Type = r.GetString(5),
            Rule = Text(6),
            Severity = r.GetString(7),
            Title = r.GetString(8),
            DedupKey = r.GetString(9),
            EvidenceRef = Text(10),
            ExpectedRef = Text(11),
            RelatedFindingId = Text(12),
            SourceState = r.GetString(13),
            AnalystState = r.GetString(14),
            RemediationStage = Text(15),
            FirstObservedAt = Parse(r.GetString(16)),
            LastObservedAt = Parse(r.GetString(17)),
            ObservationCount = r.GetInt32(18),
            AbsentCount = r.GetInt32(19),
            ReopenedCount = r.GetInt32(20),
            SourceResolvedAt = Text(21) is { } resolved ? Parse(resolved) : null,
            PayloadJson = Text(22),
            CreatedAt = Parse(r.GetString(23)),
            UpdatedAt = Parse(r.GetString(24)),
            ClientSlug = r.GetString(25),
            ClientName = r.GetString(26),
            Domain = Text(27),
            OpenException = open,
        };
    }

    private static FindingEvent ReadEvent(SqliteDataReader r, int offset)
    {
        string? Text(int i) => r.IsDBNull(offset + i) ? null : r.GetString(offset + i);

        return new FindingEvent
        {
            Id = r.GetString(offset),
            FindingId = r.GetString(offset + 1),
            At = Parse(r.GetString(offset + 2)),
            Kind = r.GetString(offset + 3),
            Actor = r.GetString(offset + 4),
            FromValue = Text(5),
            ToValue = Text(6),
            Note = Text(7),
            PayloadJson = Text(8),
        };
    }

    private static FindingExceptionRecord? ReadException(SqliteDataReader r, int offset)
    {
        string? Text(int i) => r.IsDBNull(offset + i) ? null : r.GetString(offset + i);

        return new FindingExceptionRecord
        {
            Id = r.GetString(offset),
            TenantId = r.GetString(offset + 1),
            ClientId = r.GetString(offset + 2),
            FindingId = r.GetString(offset + 3),
            Reason = r.GetString(offset + 4),
            Approver = r.GetString(offset + 5),
            CompensatingControl = r.GetString(offset + 6),
            ApprovedAt = Parse(r.GetString(offset + 7)),
            ReviewAt = Parse(r.GetString(offset + 8)),
            ExpiresAt = Text(9) is { } e ? Parse(e) : null,
            EndedAt = Text(10) is { } ended ? Parse(ended) : null,
            EndedReason = Text(11),
            CreatedBy = r.GetString(offset + 12),
            CreatedAt = Parse(r.GetString(offset + 13)),
        };
    }

    private static void AddIn(SqliteCommand command, List<string> where, string column, string prefix, IReadOnlyList<string>? values)
    {
        if (values is null || values.Count == 0) { return; }

        var names = new List<string>(values.Count);
        for (var i = 0; i < values.Count; i++)
        {
            var name = "$" + prefix + i.ToString(CultureInfo.InvariantCulture);
            names.Add(name);
            command.Parameters.AddWithValue(name, values[i]);
        }
        where.Add($"{column} IN ({string.Join(",", names)})");
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return db;
    }

    internal static int Rank(string severity) => severity switch
    {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    };

    internal static string Stamp(DateTimeOffset when) =>
        when.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    internal static DateTimeOffset Parse(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value)
            ? value
            : DateTimeOffset.MinValue;
}
