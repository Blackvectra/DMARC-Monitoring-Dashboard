using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Intelligence;

/// <summary>A human's verdict on a source. The one thing not derived from data.</summary>
public enum IndicatorClassification
{
    /// <summary>Derived, not yet judged.</summary>
    Suspected,

    /// <summary>Confirmed as impersonating a client.</summary>
    ConfirmedMalicious,

    /// <summary>A real service. Stops it being reported as a threat anywhere.</summary>
    KnownGood,

    /// <summary>Real but not worth reporting. A noisy forwarder, say.</summary>
    Ignored,
}

public sealed record ThreatIndicator
{
    public required string Value { get; init; }
    public string IndicatorType { get; init; } = "ip";

    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }

    public int ClientCount { get; init; }
    public int DomainCount { get; init; }
    public long MessageCount { get; init; }

    public bool EverAuthenticated { get; init; }

    /// <summary>
    /// Tried to sign AS a victim domain and failed.
    /// </summary>
    /// <remarks>
    /// The strongest single signal here. A misconfigured sender signs as
    /// itself; a forger signs as the domain it is pretending to be. One is a
    /// job for the client's IT, the other is an attack.
    /// </remarks>
    public bool AttemptedForgery { get; init; }

    public IReadOnlyList<string> ForgedSelectors { get; init; } = [];
    public IReadOnlyList<string> Domains { get; init; } = [];

    public IndicatorClassification Classification { get; init; } = IndicatorClassification.Suspected;
    public string Notes { get; init; } = "";

    /// <summary>Seen against several unrelated clients.</summary>
    public bool IsCrossClient => ClientCount > 1;

    /// <summary>
    /// Seen against several domains, whoever they are billed to.
    /// </summary>
    /// <remarks>
    /// This, not IsCrossClient, is what the confidence rating uses. A domain
    /// that has not been assigned to a client yet still counts: reports arrive
    /// before anybody onboards a domain, and a source working through three
    /// unassigned domains is exactly as interesting as one working through
    /// three assigned ones. Keying the signal off client assignment would mean
    /// the intelligence only appears after somebody does paperwork.
    /// </remarks>
    public bool IsMultiTarget => DomainCount > 1 || ClientCount > 1;

    /// <summary>
    /// How confident this is a threat rather than a misconfiguration, on
    /// evidence rather than a score nobody can explain.
    /// </summary>
    public IndicatorConfidence Confidence =>
        Classification == IndicatorClassification.ConfirmedMalicious ? IndicatorConfidence.Confirmed
        : Classification is IndicatorClassification.KnownGood or IndicatorClassification.Ignored ? IndicatorConfidence.NotAThreat
        : AttemptedForgery ? IndicatorConfidence.High
        : IsMultiTarget && !EverAuthenticated ? IndicatorConfidence.High
        : !EverAuthenticated ? IndicatorConfidence.Medium
        : IndicatorConfidence.Low;

    /// <summary>Why it is rated that way, so an operator can disagree with the reasoning.</summary>
    public string Rationale => Classification switch
    {
        IndicatorClassification.ConfirmedMalicious => "Confirmed by an operator.",
        IndicatorClassification.KnownGood => "Marked as a real service by an operator.",
        IndicatorClassification.Ignored => "Marked as not worth reporting by an operator.",
        _ when AttemptedForgery =>
            $"Attempted to sign as a client domain using selector {string.Join(", ", ForgedSelectors)} and failed. "
          + "A misconfigured sender signs as itself; only a forger signs as its target.",
        _ when IsMultiTarget && !EverAuthenticated =>
            $"Authenticated nothing, against {DomainCount} unrelated domains"
          + (ClientCount > 1 ? $" across {ClientCount} clients" : "")
          + ". One would be noise; several is somebody working through a list.",
        _ when !EverAuthenticated =>
            "Authenticated nothing. Either a service nobody recorded, or somebody sending as the domain.",
        _ => "Authenticated for its own domain, so most likely a real service set up unaligned.",
    };
}

public enum IndicatorConfidence { NotAThreat, Low, Medium, High, Confirmed }

/// <summary>Fleet-wide numbers, for the operator rather than for a client.</summary>
public sealed record FleetSummary
{
    public int Clients { get; init; }
    public int Domains { get; init; }
    public int DomainsEnforcing { get; init; }
    public int DomainsAtNone { get; init; }
    public int DomainsSilent { get; init; }

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }

    public int Indicators { get; init; }

    /// <summary>
    /// Sources seen against more than one domain. Counted by DOMAIN rather
    /// than by client, because a domain with no client assigned yet is still a
    /// target, and gating the signal on paperwork would hide it.
    /// </summary>
    public int MultiTargetIndicators { get; init; }
    public int ForgeryAttempts { get; init; }

    /// <summary>
    /// Fleet pass rate.
    /// </summary>
    /// <remarks>
    /// Weighted by message volume, and deliberately NOT presented as a health
    /// score. It answers "how much of the mail we watch authenticates", which
    /// is a real question. It does not answer "is anything wrong", because one
    /// broken domain among twenty disappears into it. That question is the
    /// triage list's job, and the two must never be swapped.
    /// </remarks>
    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);

    public double EnforcementRate => Domains == 0 ? 0 : Math.Round(DomainsEnforcing * 100.0 / Domains, 1);
}

/// <summary>
/// Derives and stores what this operator knows about sources impersonating
/// their clients.
///
/// The value compounds. A source classified once is classified for every
/// client, including ones onboarded later that were never exposed to it, and
/// the more domains an operator watches the sooner a campaign becomes visible.
/// A single-tenant tool cannot accumulate this at all: it only ever sees one
/// company's mail.
/// </summary>
public sealed class ThreatIntelligenceService(string databasePath)
{
    private readonly string _readOnly = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    private readonly string _readWrite = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
    }.ToString();

    /// <summary>
    /// Recomputes indicators from the reports.
    /// </summary>
    /// <remarks>
    /// Derived rather than appended, so it cannot drift from what the reports
    /// actually say. A human's classification survives the refresh, because
    /// that is the one part not recoverable from data.
    /// </remarks>
    public async Task<int> RefreshAsync(int days = 90, CancellationToken ct = default)
    {
        var since = Iso(DateTimeOffset.UtcNow.AddDays(-days));

        await using var db = new SqliteConnection(_readWrite);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = (SqliteTransaction)await db.BeginTransactionAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.Transaction = tx;

        // Everything below is one pass over the failing records. Overrides are
        // excluded: a mailing list breaking authentication is expected and
        // would bury real findings.
        command.CommandText = """
            INSERT INTO threat_indicators
              (id, tenant_id, indicator_type, value, first_seen, last_seen,
               client_count, domain_count, message_count,
               ever_authenticated, attempted_forgery, forged_selectors, updated_at)
            SELECT
              lower(hex(randomblob(16))),
              r.tenant_id,
              'ip',
              r.source_ip,
              MIN(r.date_begin),
              MAX(r.date_begin),
              COUNT(DISTINCT r.client_id),
              COUNT(DISTINCT r.domain_id),
              SUM(r.message_count),
              MAX(CASE WHEN r.dkim_auth_result = 'pass' OR r.spf_auth_result = 'pass' THEN 1 ELSE 0 END),
              -- Forgery: signed AS the domain it was sending as, and failed.
              MAX(CASE WHEN r.dkim_auth_result = 'fail'
                        AND r.dkim_domain IS NOT NULL
                        AND r.dkim_domain = r.header_from THEN 1 ELSE 0 END),
              GROUP_CONCAT(DISTINCT CASE WHEN r.dkim_auth_result = 'fail'
                                          AND r.dkim_domain = r.header_from
                                         THEN r.dkim_selector END),
              $now
            FROM aggregate_records r
            WHERE r.dmarc_result = 'fail'
              AND r.date_begin >= $since
              AND (r.override_reason IS NULL OR r.override_reason = '')
            GROUP BY r.tenant_id, r.source_ip
            ON CONFLICT(tenant_id, indicator_type, value) DO UPDATE SET
              first_seen        = MIN(first_seen, excluded.first_seen),
              last_seen         = MAX(last_seen, excluded.last_seen),
              client_count      = excluded.client_count,
              domain_count      = excluded.domain_count,
              message_count     = excluded.message_count,
              ever_authenticated= excluded.ever_authenticated,
              attempted_forgery = excluded.attempted_forgery,
              forged_selectors  = excluded.forged_selectors,
              updated_at        = excluded.updated_at
            -- classification, classified_by, classified_at and notes are NOT
            -- touched: a human's judgement must survive a refresh.
            """;
        command.Parameters.AddWithValue("$since", since);
        command.Parameters.AddWithValue("$now", Iso(DateTimeOffset.UtcNow));

        var affected = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await tx.CommitAsync(ct).ConfigureAwait(false);
        return affected;
    }

    /// <summary>Indicators worth an operator's attention, strongest first.</summary>
    public async Task<IReadOnlyList<ThreatIndicator>> GetIndicatorsAsync(
        bool includeDismissed = false, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_readOnly);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT i.value, i.indicator_type, i.first_seen, i.last_seen,
                   i.client_count, i.domain_count, i.message_count,
                   i.ever_authenticated, i.attempted_forgery, i.forged_selectors,
                   i.classification, COALESCE(i.notes, ''),
                   (SELECT GROUP_CONCAT(DISTINCT d.name)
                      FROM aggregate_records r JOIN domains d ON d.id = r.domain_id
                     WHERE r.source_ip = i.value AND r.dmarc_result = 'fail')
            FROM threat_indicators i
            {(includeDismissed ? "" : "WHERE i.classification NOT IN ('known_good','ignored')")}
            ORDER BY i.attempted_forgery DESC, i.client_count DESC, i.message_count DESC
            """;

        var results = new List<ThreatIndicator>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new ThreatIndicator
            {
                Value = reader.GetString(0),
                IndicatorType = reader.GetString(1),
                FirstSeen = ParseDate(reader.GetString(2)),
                LastSeen = ParseDate(reader.GetString(3)),
                ClientCount = reader.GetInt32(4),
                DomainCount = reader.GetInt32(5),
                MessageCount = reader.GetInt64(6),
                EverAuthenticated = reader.GetInt32(7) == 1,
                AttemptedForgery = reader.GetInt32(8) == 1,
                ForgedSelectors = Split(reader.IsDBNull(9) ? "" : reader.GetString(9)),
                Classification = ParseClassification(reader.GetString(10)),
                Notes = reader.GetString(11),
                Domains = Split(reader.IsDBNull(12) ? "" : reader.GetString(12)),
            });
        }
        return results;
    }

    /// <summary>Records a human's verdict. Survives every later refresh.</summary>
    public async Task ClassifyAsync(
        string value, IndicatorClassification classification, string by, string notes = "", CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        await using var db = new SqliteConnection(_readWrite);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            UPDATE threat_indicators
               SET classification = $class, classified_by = $by, classified_at = $now, notes = $notes
             WHERE value = $value
            """;
        command.Parameters.AddWithValue("$class", ToDb(classification));
        command.Parameters.AddWithValue("$by", by ?? "");
        command.Parameters.AddWithValue("$now", Iso(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$notes", notes ?? "");
        command.Parameters.AddWithValue("$value", value);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Everything the operator watches, in one set of numbers.</summary>
    public async Task<FleetSummary> GetFleetSummaryAsync(int days = 30, CancellationToken ct = default)
    {
        var since = Iso(DateTimeOffset.UtcNow.AddDays(-days));

        await using var db = new SqliteConnection(_readOnly);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT
              (SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL),
              (SELECT COUNT(*) FROM domains WHERE deleted_at IS NULL AND is_active = 1),
              (SELECT COUNT(*) FROM (
                 SELECT d.id, (SELECT ar.policy_p FROM aggregate_reports ar
                                WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1) AS p
                   FROM domains d WHERE d.deleted_at IS NULL AND d.is_active = 1)
                WHERE p IN ('reject','quarantine')),
              (SELECT COUNT(*) FROM (
                 SELECT d.id, (SELECT ar.policy_p FROM aggregate_reports ar
                                WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1) AS p
                   FROM domains d WHERE d.deleted_at IS NULL AND d.is_active = 1)
                WHERE p = 'none'),
              (SELECT COUNT(*) FROM domains d
                WHERE d.deleted_at IS NULL AND d.is_active = 1
                  AND NOT EXISTS (SELECT 1 FROM aggregate_reports ar WHERE ar.domain_id = d.id)),
              (SELECT COALESCE(SUM(message_count), 0) FROM aggregate_records WHERE date_begin >= $since),
              (SELECT COALESCE(SUM(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0)
                 FROM aggregate_records WHERE date_begin >= $since),
              (SELECT COUNT(*) FROM threat_indicators WHERE classification NOT IN ('known_good','ignored')),
              (SELECT COUNT(*) FROM threat_indicators
                WHERE (client_count > 1 OR domain_count > 1)
                  AND classification NOT IN ('known_good','ignored')),
              (SELECT COUNT(*) FROM threat_indicators WHERE attempted_forgery = 1 AND classification NOT IN ('known_good','ignored'))
            """;
        command.Parameters.AddWithValue("$since", since);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return new FleetSummary(); }

        var messages = reader.GetInt64(5);
        var passing = reader.GetInt64(6);

        return new FleetSummary
        {
            Clients = reader.GetInt32(0),
            Domains = reader.GetInt32(1),
            DomainsEnforcing = reader.GetInt32(2),
            DomainsAtNone = reader.GetInt32(3),
            DomainsSilent = reader.GetInt32(4),
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            Indicators = reader.GetInt32(7),
            MultiTargetIndicators = reader.GetInt32(8),
            ForgeryAttempts = reader.GetInt32(9),
        };
    }

    /// <summary>
    /// The indicator list as plain text, one value per line.
    /// </summary>
    /// <remarks>
    /// So it can be fed to a firewall, a SIEM or a block list. An MSP that
    /// already runs security tooling should be able to use what this learns
    /// without copying it out by hand.
    ///
    /// Only confirmed and high-confidence entries are exported. Shipping
    /// "suspected" into a blocking device is how a client's own mail server
    /// ends up on a deny list.
    /// </remarks>
    public async Task<string> ExportAsync(CancellationToken ct = default)
    {
        var indicators = await GetIndicatorsAsync(includeDismissed: false, ct).ConfigureAwait(false);

        var lines = new List<string>
        {
            "# DMARC Monitor threat indicators",
            $"# Generated {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm} UTC",
            "# Confirmed and high-confidence only. Suspected entries are excluded",
            "# deliberately: blocking on a guess takes a client's own mail down.",
            "",
        };

        foreach (var i in indicators.Where(i =>
            i.Confidence is IndicatorConfidence.Confirmed or IndicatorConfidence.High))
        {
            lines.Add($"{i.Value}    # {i.Confidence}, {i.DomainCount} domain(s), {i.MessageCount} message(s). {i.Rationale}");
        }

        return string.Join('\n', lines);
    }

    private static List<string> Split(string value) =>
        [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Distinct(StringComparer.OrdinalIgnoreCase)
                 .OrderBy(v => v, StringComparer.Ordinal)];

    private static DateTimeOffset ParseDate(string raw) =>
        DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
            ? new DateTimeOffset(d, TimeSpan.Zero)
            : DateTimeOffset.MinValue;

    private static IndicatorClassification ParseClassification(string raw) => raw switch
    {
        "confirmed_malicious" => IndicatorClassification.ConfirmedMalicious,
        "known_good" => IndicatorClassification.KnownGood,
        "ignored" => IndicatorClassification.Ignored,
        _ => IndicatorClassification.Suspected,
    };

    private static string ToDb(IndicatorClassification c) => c switch
    {
        IndicatorClassification.ConfirmedMalicious => "confirmed_malicious",
        IndicatorClassification.KnownGood => "known_good",
        IndicatorClassification.Ignored => "ignored",
        _ => "suspected",
    };

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
