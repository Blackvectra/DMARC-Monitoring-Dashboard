using System.Globalization;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Rollout;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Domains;

/// <summary>One sending source, as seen for a single domain.</summary>
public sealed record DomainSource
{
    public required string SourceIp { get; init; }
    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }

    /// <summary>
    /// What this source proved when it FAILED.
    /// </summary>
    /// <remarks>
    /// Scoped to the failing rows on purpose. Taken across everything a source
    /// sent, one that authenticates properly most of the time and fails once
    /// having proved nothing looks like a service of the customer's own that
    /// needs adjusting, and the message nobody could account for disappears.
    /// </remarks>
    public string AuthenticatedFor { get; init; } = "";

    /// <summary>Other clients this same address was seen failing against.</summary>
    public int OtherClients { get; init; }

    public DateTimeOffset? LastSeen { get; init; }

    public bool IsClean => Failing == 0;
    public bool Authenticated => !string.IsNullOrEmpty(AuthenticatedFor);

    /// <summary>What this most likely is, in one word, for the badge.</summary>
    public SourceVerdict Verdict =>
        IsClean ? SourceVerdict.Misconfigured   // unused for clean rows; the page branches on IsClean first
        : Authenticated ? SourceVerdict.Misconfigured
        : OtherClients > 0 ? SourceVerdict.CrossClientImpersonation
        : SourceVerdict.Unauthenticated;
}

/// <summary>A receiver that sent reports about this domain.</summary>
public sealed record DomainReporter
{
    public required string OrgName { get; init; }
    public int Reports { get; init; }
    public DateTimeOffset? LastReport { get; init; }
}

/// <summary>Everything the domain page shows.</summary>
public sealed record DomainDetail
{
    public required string Domain { get; init; }
    public required string ClientName { get; init; }
    public required string ClientSlug { get; init; }

    public string Policy { get; init; } = "none";
    public string SubdomainPolicy { get; init; } = "";
    public int Pct { get; init; } = 100;
    public string PolicyTarget { get; init; } = "reject";

    public DateTimeOffset? BaselineStarted { get; init; }
    public int BaselineDays { get; init; } = 14;

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing => Messages - Passing;
    public DateTimeOffset? LastReport { get; init; }

    /// <summary>
    /// Messages the receiver overrode - forwarded, or its own local policy.
    /// </summary>
    /// <remarks>
    /// Counted in Messages but deliberately absent from the source tables,
    /// because a mailing list breaking authentication is expected and would
    /// bury the findings that matter. That makes the tables sum to less than
    /// the headline, which on the live data is 7,970 against 8,018 for one
    /// domain. Unexplained, that gap reads as a bug in the arithmetic, so the
    /// page states it.
    /// </remarks>
    public long OverriddenMessages { get; init; }

    public IReadOnlyList<DomainSource> Sources { get; init; } = [];
    public IReadOnlyList<DomainReporter> Reporters { get; init; } = [];

    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);

    public IReadOnlyList<DomainSource> Clean =>
        [.. Sources.Where(s => s.IsClean).OrderByDescending(s => s.Messages)];

    /// <summary>
    /// Real senders losing this domain's mail: its own paths that break
    /// sometimes, and third-party services signing as themselves.
    /// </summary>
    public IReadOnlyList<DomainSource> Misconfigured =>
        [.. Sources.Where(s => !s.IsClean && (s.Passing > 0 || s.Authenticated))
                   .OrderByDescending(s => s.Failing)];

    /// <summary>
    /// Sources that have never once sent authenticated mail for this domain.
    /// </summary>
    /// <remarks>
    /// Passing even once is the thing a forger cannot do, so it outranks what
    /// any single failing row looks like. Without that, a gateway signing on
    /// the customer's behalf - which breaks a share of its own signatures in
    /// transit - lands here, and the page accuses the customer's own
    /// infrastructure of impersonating them.
    /// </remarks>
    public IReadOnlyList<DomainSource> Impersonating =>
        [.. Sources.Where(s => !s.IsClean && s.Passing == 0 && !s.Authenticated)
                   .OrderByDescending(s => s.Failing)];

    public TriageLevel Level { get; init; } = TriageLevel.Fine;
    public string Headline { get; init; } = "";
}

/// <summary>
/// Everything about one domain, for the page an operator opens from triage.
///
/// The triage list says what needs doing; this says why, with the evidence
/// underneath it. It is deliberately one round trip per section rather than
/// one large join: a domain with no sources still has to render its policy and
/// its reporters, and a join would collapse those rows away.
/// </summary>
public sealed class DomainDetailService(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    public async Task<DomainDetail?> GetAsync(string domain, int days = 30, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var since = DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        string domainId, clientName, clientSlug;
        DateTimeOffset? baseline;
        int baselineDays;
        string target;

        await using (var head = db.CreateCommand())
        {
            head.CommandText = """
                SELECT d.id, c.name, c.slug, d.baseline_started_at, d.baseline_days, d.policy_target
                FROM domains d
                JOIN clients c ON c.id = d.client_id
                WHERE d.name = $name
                LIMIT 1
                """;
            head.Parameters.AddWithValue("$name", name);

            await using var reader = await head.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

            domainId = reader.GetString(0);
            clientName = reader.GetString(1);
            clientSlug = reader.GetString(2);
            baseline = reader.IsDBNull(3) ? null : ParseDate(reader.GetString(3));
            baselineDays = reader.IsDBNull(4) ? 14 : reader.GetInt32(4);
            target = reader.IsDBNull(5) ? "reject" : reader.GetString(5);
        }

        var (policy, subPolicy, pct, lastReport) = await PolicyAsync(db, domainId, ct).ConfigureAwait(false);
        var (messages, passing, overridden) = await TotalsAsync(db, domainId, since, ct).ConfigureAwait(false);
        var sources = await SourcesAsync(db, domainId, since, ct).ConfigureAwait(false);
        var reporters = await ReportersAsync(db, domainId, since, ct).ConfigureAwait(false);

        var detail = new DomainDetail
        {
            Domain = name,
            ClientName = clientName,
            ClientSlug = clientSlug,
            Policy = policy,
            SubdomainPolicy = subPolicy,
            Pct = pct,
            PolicyTarget = target,
            BaselineStarted = baseline,
            BaselineDays = baselineDays,
            Messages = messages,
            Passing = passing,
            OverriddenMessages = overridden,
            LastReport = lastReport,
            Sources = sources,
            Reporters = reporters,
        };

        // The same judgement the triage list made, so the two pages cannot
        // disagree about the same domain.
        var verdict = RolloutAssessment.Assess(new DomainState
        {
            Domain = name,
            Policy = policy,
            PolicyTarget = target,
            Messages = messages,
            Passing = passing,
            FailingSources = detail.Misconfigured.Count + detail.Impersonating.Count,
            LastReport = lastReport,
            BaselineStarted = baseline,
            BaselineDays = baselineDays,
        });

        return detail with { Level = verdict.Level, Headline = verdict.Headline };
    }

    private static async Task<(string Policy, string Sub, int Pct, DateTimeOffset? Last)> PolicyAsync(
        SqliteConnection db, string domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // The most recent report wins. An older one describes a policy that
        // may since have been changed, which is the thing an operator is most
        // often checking on this page.
        //
        // received_at breaks the tie, because date_end alone does not:
        // receivers send several reports covering the same window, and during
        // a rollout two of them can disagree about the policy. Without a
        // tie-break SQLite picks whichever it likes, so the page can show a
        // policy that was superseded hours ago and be right again on the next
        // refresh, which is the hardest kind of wrong to notice.
        command.CommandText = """
            SELECT policy_p, COALESCE(policy_sp, ''), COALESCE(policy_pct, 100), date_end
            FROM aggregate_reports
            WHERE domain_id = $domain
            ORDER BY date_end DESC, received_at DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$domain", domainId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return ("none", "", 100, null); }

        return (
            reader.IsDBNull(0) ? "none" : reader.GetString(0),
            reader.GetString(1),
            reader.GetInt32(2),
            reader.IsDBNull(3) ? null : ParseDate(reader.GetString(3)));
    }

    private static async Task<(long Messages, long Passing, long Overridden)> TotalsAsync(
        SqliteConnection db, string domainId, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // The overridden count comes from the same pass as the total, so the
        // figure explaining the gap cannot itself be computed over a different
        // set of rows from the gap it explains.
        //
        // Counted only where the message also FAILED. An override is just the
        // receiver saying it did not apply the requested policy, and it says
        // that about mail that passed as well: Microsoft stamps "SPF ignored
        // due to local policy" on traffic that authenticated perfectly well by
        // DKIM. Counting those as "left out" removed a domain's own clean mail
        // from the source tables and then described it to the operator in the
        // same breath as forwarded failures - on the live data, 19 of
        // mortonnd.gov's 84 messages, which is its own mail servers.
        command.CommandText = """
            SELECT COALESCE(SUM(message_count), 0),
                   COALESCE(SUM(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0),
                   COALESCE(SUM(CASE WHEN dmarc_result <> 'pass'
                                      AND override_reason IS NOT NULL AND override_reason <> ''
                                     THEN message_count END), 0)
            FROM aggregate_records
            WHERE domain_id = $domain AND date_begin >= $since
            """;
        command.Parameters.AddWithValue("$domain", domainId);
        command.Parameters.AddWithValue("$since", since);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return (0, 0, 0); }
        return (reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
    }

    private static async Task<List<DomainSource>> SourcesAsync(
        SqliteConnection db, string domainId, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT r.source_ip,
                   SUM(r.message_count),
                   SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count ELSE 0 END),
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT
                     CASE WHEN r.dmarc_result = 'fail' AND r.dkim_auth_result = 'pass' THEN r.dkim_domain
                          WHEN r.dmarc_result = 'fail' AND r.spf_auth_result  = 'pass' THEN r.spf_domain END), ''), ''),
                   (SELECT COUNT(DISTINCT o.client_id)
                      FROM aggregate_records o
                     WHERE o.source_ip = r.source_ip
                       AND o.domain_id <> $domain
                       AND o.dmarc_result = 'fail'),
                   MAX(r.date_begin)
            FROM aggregate_records r
            WHERE r.domain_id = $domain AND r.date_begin >= $since
              -- Overridden FAILURES only. A mailing list breaking
              -- authentication is expected and buries the findings that
              -- matter, so it stays out; a source whose mail passed and merely
              -- carried a receiver note belongs in the table like any other.
              AND NOT (r.dmarc_result <> 'pass'
                       AND r.override_reason IS NOT NULL AND r.override_reason <> '')
            GROUP BY r.source_ip
            ORDER BY SUM(r.message_count) DESC
            """;
        command.Parameters.AddWithValue("$domain", domainId);
        command.Parameters.AddWithValue("$since", since);

        var results = new List<DomainSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var messages = reader.GetInt64(1);
            var passing = reader.GetInt64(2);

            results.Add(new DomainSource
            {
                SourceIp = reader.GetString(0),
                Messages = messages,
                Passing = passing,
                Failing = messages - passing,
                AuthenticatedFor = reader.IsDBNull(3) ? "" : reader.GetString(3),
                OtherClients = reader.IsDBNull(4) ? 0 : reader.GetInt32(4),
                LastSeen = reader.IsDBNull(5) ? null : ParseDate(reader.GetString(5)),
            });
        }
        return results;
    }

    private static async Task<List<DomainReporter>> ReportersAsync(
        SqliteConnection db, string domainId, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Who is reporting matters as much as what they say. A domain heard
        // from by one receiver is a domain whose picture is partial, and an
        // operator reading a clean pass rate should be able to see that.
        command.CommandText = """
            SELECT org_name, COUNT(*), MAX(date_end)
            FROM aggregate_reports
            WHERE domain_id = $domain AND date_end >= $since
            GROUP BY org_name
            ORDER BY COUNT(*) DESC
            """;
        command.Parameters.AddWithValue("$domain", domainId);
        command.Parameters.AddWithValue("$since", since);

        var results = new List<DomainReporter>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new DomainReporter
            {
                OrgName = reader.GetString(0),
                Reports = reader.GetInt32(1),
                LastReport = reader.IsDBNull(2) ? null : ParseDate(reader.GetString(2)),
            });
        }
        return results;
    }

    private static DateTimeOffset? ParseDate(string raw) =>
        DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
            ? new DateTimeOffset(d, TimeSpan.Zero)
            : null;
}
