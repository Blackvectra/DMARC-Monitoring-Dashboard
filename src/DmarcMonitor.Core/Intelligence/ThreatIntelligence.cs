using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DmarcMonitor.Core.Aggregate;
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

    /// <summary>
    /// <see cref="Value"/> with anything that is not printable taken out, for
    /// a terminal or a file.
    /// </summary>
    /// <remarks>
    /// The value came out of a report, and reports are whatever their sender
    /// typed. Stored before addresses were checked, a value could carry a
    /// newline or an escape sequence into an operator's terminal. The raw
    /// value stays the key a verdict is recorded against.
    /// </remarks>
    public string DisplayValue => ThreatIntelligenceService.Printable(Value);

    public string IndicatorType { get; init; } = "ip";

    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }

    public int ClientCount { get; init; }
    public long MessageCount { get; init; }

    /// <summary>
    /// How many domains this was seen against. Derived from the names rather
    /// than stored beside them, so a headline saying "3 domain(s)" cannot sit
    /// above a list of four - which is what happened when the count came from
    /// a windowed aggregate and the names came from an unwindowed lookup.
    /// </summary>
    public int DomainCount => Domains.Count;

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

    /// <summary>
    /// The address's reverse name, only when its own forward records point
    /// back at it; otherwise null.
    /// </summary>
    public string? ConfirmedName { get; init; }

    /// <summary>What a confirmed name says this is, when the catalogue knows it.</summary>
    public SourceIdentity? VerifiedIdentity => SourceCatalog.Identify(ConfirmedName);

    /// <summary>
    /// A mail security gateway or a mail platform, by a name its owner's DNS
    /// confirms.
    /// </summary>
    /// <remarks>
    /// Passes mail on rather than sending it, so whatever failed through it
    /// started somewhere else. Forward-confirmed because the PTR alone is the
    /// sender's own word: a forger can reverse to a gateway's hostname, and
    /// cannot make the gateway's DNS name it back.
    /// </remarks>
    public bool IsVerifiedRelay =>
        VerifiedIdentity is { Kind: SourceKind.SecurityGateway or SourceKind.MailProvider };

    /// <summary>
    /// Domains of this organization the address delivered DMARC-passing mail
    /// for in the same window.
    /// </summary>
    /// <remarks>
    /// Not an excuse - a success for one domain does not excuse forging
    /// another, and the rating ignores it. It is what makes an address unsafe
    /// to BLOCK: a firewall that drops it drops that client's own mail with
    /// the rest. The export reads it for exactly that.
    /// </remarks>
    public IReadOnlyList<string> DomainsItDeliveredFor { get; init; } = [];

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
        : IsVerifiedRelay ? IndicatorConfidence.NotAThreat
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
        // "Only a forger signs as its target" was wrong, and wrong in the
        // direction that gets a customer's own security vendor reported as an
        // attacker. A gateway that re-signs mail in transit - Avanan, Mimecast,
        // Proofpoint - signs as the domain it is carrying, and breaks its own
        // signature doing it, which is character for character what this
        // detects. Found on a real estate: 35.174.145.124 against two clients,
        // rated High with that sentence, reversing to us.cloud-sec-av.com.
        //
        // A PTR on its own is written by whoever holds the address, so a
        // friendly name is not evidence and never softens a verdict; the
        // sentence below states both explanations and the question that
        // separates them. A FORWARD-CONFIRMED name is different: the gateway's
        // own DNS naming the address back is not something a forger can
        // write, and that one is taken as what it is.
        _ when IsVerifiedRelay =>
            $"{VerifiedIdentity!.Value.Name}, confirmed by its own forward DNS ({ConfirmedName}). It passes mail on "
          + "rather than sending it: whatever failed through it started somewhere else, and blocking it would "
          + "stop every message it carries, your clients' own included.",
        _ when AttemptedForgery =>
            $"Signed as a client domain using selector {string.Join(", ", ForgedSelectors)}, and the "
          + "signature failed. A third-party service normally signs as itself, so this is either "
          + "somebody forging the domain or a gateway re-signing mail in transit. Ask whether the "
          + "customer uses a mail security gateway: if they do not, treat it as forgery.",
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
    /// <summary>
    /// How many days the message figures cover.
    /// </summary>
    /// <remarks>
    /// The counts of clients and domains are current, while the message totals
    /// are windowed. Printing both without saying which is which invites an
    /// operator to reconcile them against each other and find they do not add
    /// up, so the window travels with the numbers.
    /// </remarks>
    public int WindowDays { get; init; } = 30;

    public int Clients { get; init; }
    public int Domains { get; init; }
    public int DomainsEnforcing { get; init; }
    public int DomainsAtNone { get; init; }
    /// <summary>
    /// Domains not heard from recently, whether they ever were.
    /// </summary>
    /// <remarks>
    /// The same threshold the triage list uses, so the headline and the list
    /// cannot disagree about whether a domain has gone quiet.
    /// </remarks>
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
    /// <summary>How far back indicators are derived from, unless a caller says otherwise.</summary>
    public const int WindowDays = 90;

    public async Task<int> RefreshAsync(int days = WindowDays, CancellationToken ct = default)
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
               ever_authenticated, attempted_forgery, forged_selectors, domains, updated_at)
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
              -- Forgery: signed AS the domain it was sending as, failed, and
              -- has NEVER signed successfully for that domain from this
              -- address. The last clause is what keeps a relay out of it. A
              -- mail gateway carrying a customer's own outbound signs as the
              -- customer and breaks a proportion of its own signatures in
              -- transit, which looks identical to forgery row by row. Judged
              -- on the whole address, the two separate cleanly: a relay also
              -- produces passing signatures for that same domain, and a
              -- forger never does.
              MAX(CASE WHEN r.dkim_auth_result = 'fail'
                        AND r.dkim_domain IS NOT NULL
                        AND r.dkim_domain = r.header_from
                        AND NOT EXISTS (
                              SELECT 1 FROM aggregate_records ok
                               WHERE ok.source_ip = r.source_ip
                                 AND ok.dkim_domain = r.dkim_domain
                                 AND ok.dkim_auth_result = 'pass')
                       THEN 1 ELSE 0 END),
              GROUP_CONCAT(DISTINCT CASE WHEN r.dkim_auth_result = 'fail'
                                          AND r.dkim_domain = r.header_from
                                          AND NOT EXISTS (
                                                SELECT 1 FROM aggregate_records ok
                                                 WHERE ok.source_ip = r.source_ip
                                                   AND ok.dkim_domain = r.dkim_domain
                                                   AND ok.dkim_auth_result = 'pass')
                                         THEN r.dkim_selector END),
              -- Same pass, same window, same rows as domain_count above.
              GROUP_CONCAT(DISTINCT d.name),
              $now
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
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
              domains           = excluded.domains,
              updated_at        = excluded.updated_at
            -- classification, classified_by, classified_at and notes are NOT
            -- touched: a human's judgment must survive a refresh.
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

        // Before 0018 no name is confirmed, and an unconfirmed name decides
        // nothing - the safe way round for a database not yet upgraded.
        var confirmedName = await HasColumnAsync(db, "source_names", "forward_confirmed", ct).ConfigureAwait(false)
            ? "(SELECT n.reverse_name FROM source_names n WHERE n.ip = i.value AND n.forward_confirmed = 1)"
            : "NULL";

        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT i.value, i.indicator_type, i.first_seen, i.last_seen,
                   i.client_count, i.domain_count, i.message_count,
                   i.ever_authenticated, i.attempted_forgery, i.forged_selectors,
                   i.classification, COALESCE(i.notes, ''), i.domains,
                   {confirmedName},
                   -- The organization's domains this address delivered
                   -- authenticated mail for, in the window a refresh reads.
                   -- Not evidence of innocence; evidence that blocking it
                   -- blocks a client. See ThreatIndicator.DomainsItDeliveredFor.
                   (SELECT GROUP_CONCAT(DISTINCT d.name)
                      FROM aggregate_records ok
                      JOIN domains d ON d.id = ok.domain_id
                     WHERE ok.tenant_id = i.tenant_id
                       AND ok.source_ip = i.value
                       AND ok.dmarc_result = 'pass'
                       AND ok.date_begin >= $since)
            FROM threat_indicators i
            {(includeDismissed ? "" : "WHERE i.classification NOT IN ('known_good','ignored')")}
            ORDER BY i.attempted_forgery DESC, i.client_count DESC, i.message_count DESC
            """;
        command.Parameters.AddWithValue("$since", Iso(DateTimeOffset.UtcNow.AddDays(-WindowDays)));

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
                MessageCount = reader.GetInt64(6),
                EverAuthenticated = reader.GetInt32(7) == 1,
                AttemptedForgery = reader.GetInt32(8) == 1,
                ForgedSelectors = Split(reader.IsDBNull(9) ? "" : reader.GetString(9)),
                Classification = ParseClassification(reader.GetString(10)),
                Notes = reader.GetString(11),
                Domains = Split(reader.IsDBNull(12) ? "" : reader.GetString(12)),
                ConfirmedName = reader.IsDBNull(13) ? null : reader.GetString(13),
                DomainsItDeliveredFor = Split(reader.IsDBNull(14) ? "" : reader.GetString(14)),
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
              -- Unassigned is where domains wait to be onboarded, not a
              -- customer. Counting it inflates the number an operator would
              -- quote, and it is the one client that can never be billed.
              (SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL AND slug <> 'unassigned'),
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
              -- Silent means "has stopped being reported on", not "never
              -- was". Counting only the latter said 0 while five of ten
              -- domains had not been heard from for between 14 and 128 days,
              -- so the headline read as calm while half the fleet had gone
              -- dark. A domain that never reported still counts: its last
              -- report is missing rather than merely old.
              (SELECT COUNT(*) FROM domains d
                WHERE d.deleted_at IS NULL AND d.is_active = 1
                  AND COALESCE((SELECT MAX(ar.date_end) FROM aggregate_reports ar
                                 WHERE ar.domain_id = d.id), '') < $silentBefore),
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
        command.Parameters.AddWithValue(
            "$silentBefore",
            Iso(DateTimeOffset.UtcNow.AddDays(-Rollout.RolloutAssessment.SilentDays)));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return new FleetSummary(); }

        var messages = reader.GetInt64(5);
        var passing = reader.GetInt64(6);

        return new FleetSummary
        {
            WindowDays = days,
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
    ///
    /// And only what is safe to BLOCK, which is a second question. Rated on
    /// its own, the list carried a customer's own Avanan gateway, INKY's
    /// relays and two Microsoft addresses - each suspicious by the letter of
    /// the rating and each a way to take a client's mail down if a firewall
    /// obeyed it. So an entry is withheld when it is not a public address,
    /// when it belongs to a platform everybody shares, or when it delivered
    /// authenticated mail for one of this organization's domains in the same
    /// window. Withheld entries are listed underneath as comments, with the
    /// reason, so nothing disappears without saying so.
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

        var withheld = new List<string>();

        foreach (var i in indicators.Where(i =>
            i.Confidence is IndicatorConfidence.Confirmed or IndicatorConfidence.High))
        {
            if (!IpText.TryParse(i.Value, out var address) || !IsPublic(address))
            {
                withheld.Add($"{i.DisplayValue}: not a public address");
                continue;
            }

            if (SenderCatalog.Identify(address.ToString()) is { } platform)
            {
                withheld.Add($"{address}: an address of {platform}, which every customer of it shares - yours included");
                continue;
            }

            if (i.DomainsItDeliveredFor.Count > 0)
            {
                withheld.Add($"{address}: delivered authenticated mail for {string.Join(", ", i.DomainsItDeliveredFor)} "
                    + "in the same period, so blocking it would stop that mail too");
                continue;
            }

            lines.Add($"{address}    # {i.Confidence}, {i.DomainCount} domain(s), {i.MessageCount} message(s). "
                + Printable(i.Rationale));
        }

        if (withheld.Count > 0)
        {
            lines.Add("");
            lines.Add($"# Withheld: {withheld.Count} rated high but not safe to block.");
            lines.AddRange(withheld.Select(w => "#   " + Printable(w)));
        }

        return string.Join('\n', lines);
    }

    /// <summary>
    /// Text fit for one line of a terminal or a file.
    /// </summary>
    /// <remarks>
    /// Selectors, domain names and addresses in an indicator come out of
    /// reports, which are unauthenticated: a selector with a newline in it
    /// wrote a second, uncommented line into the blocklist, and one with an
    /// escape sequence wrote to the operator's terminal. Control characters,
    /// line and paragraph separators and bidirectional overrides become
    /// spaces.
    /// </remarks>
    internal static string Printable(string? text)
    {
        if (string.IsNullOrEmpty(text)) { return ""; }

        var clean = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            clean.Append(char.IsControl(c) || c is '\u2028' or '\u2029' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069')
                ? ' '
                : c);
        }

        return string.Join(' ', clean.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>
    /// An address a firewall rule could mean: not private, loopback,
    /// link-local, shared address space, multicast or reserved.
    /// </summary>
    private static bool IsPublic(IPAddress address)
    {
        var ip = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] switch
            {
                0 or 10 or 127 => false,
                100 when b[1] >= 64 && b[1] <= 127 => false,   // 100.64.0.0/10, carrier-grade NAT
                169 when b[1] == 254 => false,
                172 when b[1] >= 16 && b[1] <= 31 => false,
                192 when b[1] == 168 => false,
                >= 224 => false,                                  // multicast, reserved, broadcast
                _ => true,
            };
        }

        return !(ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Loopback)
                 || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast
                 || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC);    // fc00::/7, unique local
    }

    private static List<string> Split(string value) =>
        [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Select(Printable)
                 .Where(v => v.Length > 0)
                 .Distinct(StringComparer.OrdinalIgnoreCase)
                 .OrderBy(v => v, StringComparer.Ordinal)];

    private static async Task<bool> HasColumnAsync(SqliteConnection db, string table, string column, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM pragma_table_info($table) WHERE name = $column";
        command.Parameters.AddWithValue("$table", table);
        command.Parameters.AddWithValue("$column", column);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

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
