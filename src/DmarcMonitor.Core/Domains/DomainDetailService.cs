using System.Globalization;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Rollout;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Domains;

/// <summary>
/// A signature that verified for a domain other than the one being sent as.
/// </summary>
/// <param name="Domain">The <c>d=</c> domain the signature was made with.</param>
/// <param name="Verdict">How that domain relates to the From domain.</param>
/// <param name="WouldAlignIfRelaxed">
/// True when the only thing stopping this from aligning is the domain's own
/// <c>adkim=s</c>. A different fix from the usual one, and a much smaller one.
/// </param>
public sealed record UnalignedSignature(string Domain, AlignmentVerdict Verdict, bool WouldAlignIfRelaxed);

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

    /// <summary>
    /// Signatures this source made that VERIFIED, on messages that failed DMARC
    /// anyway.
    /// </summary>
    /// <remarks>
    /// The single most misread line in a DMARC report. "dkim=pass" beside
    /// "dmarc=fail" is not a contradiction and not a broken key - it is a valid
    /// signature over the wrong domain, which DMARC discards. Left unexplained
    /// it costs an operator a day chasing a key that is working perfectly.
    /// </remarks>
    public IReadOnlyList<UnalignedSignature> UnalignedDkim { get; init; } = [];

    /// <summary>
    /// Another address that carries the same service's mail for this domain and
    /// signs it correctly, when there is one.
    /// </summary>
    /// <remarks>
    /// Worth its own field because it converts an argument into a fact. A
    /// vendor told "your mail is failing DMARC" will often say it cannot sign
    /// as a customer's domain; a vendor shown that its own other sending host
    /// already does, for this very domain, cannot.
    /// </remarks>
    public string? SameServiceSigningCorrectly { get; init; }

    /// <summary>The envelope domains seen for this source, as SPF checked them.</summary>
    public IReadOnlyList<string> EnvelopeDomains { get; init; } = [];

    /// <summary>
    /// Signing domains this source used on mail that PASSED DMARC.
    /// </summary>
    /// <remarks>
    /// The evidence behind <see cref="SameServiceSigningCorrectly"/>, and the
    /// reason it is not simply "this source passes DMARC". A source can pass
    /// while signing somebody else's domain - the live data has three addresses
    /// passing for bmcedc.com that all sign
    /// <c>antispam.mailspamprotection.com</c>, exactly the domain the failing
    /// address signs. Offered as proof, that would send an operator to a vendor
    /// claiming the vendor already signs as their customer, which it does not.
    /// </remarks>
    public IReadOnlyList<string> DkimOnPassingMail { get; init; } = [];

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

    /// <summary>Messages this receiver has ever reported on for the domain.</summary>
    public long Messages { get; init; }

    /// <summary>Its share of every message ever reported for the domain, as a percentage.</summary>
    public double Share { get; init; }

    /// <summary>Days since its last report, or null if it has never sent one.</summary>
    public int? DaysSilent { get; init; }

    /// <summary>
    /// A receiver that used to carry real volume for this domain and has
    /// stopped, while others are still reporting.
    /// </summary>
    /// <remarks>
    /// The product already notices a domain nobody reports on. It did not
    /// notice a domain whose BIGGEST reporter stops while the rest carry on,
    /// and that is the more dangerous shape: reports keep arriving, the page
    /// keeps showing a pass rate, and the pass rate is now computed over
    /// whoever is left. On the live data Enterprise Outlook carried 73.5% of
    /// mortonnd.gov's mail and stopped sending about it on 2026-07-16, while
    /// still reporting on every other domain. What was left read as 100%
    /// clean and "ready for p=reject".
    /// </remarks>
    public bool HasGoneQuiet { get; init; }
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

    /// <summary>
    /// <c>adkim=s</c>: a signature must be for this exact domain, not a
    /// subdomain of it.
    /// </summary>
    /// <remarks>
    /// Read from the reports rather than from DNS, so it describes the rule
    /// that was in force over the mail being counted. Relevant here because it
    /// decides whether a near-miss signature is a near miss at all.
    /// </remarks>
    public bool StrictDkim { get; init; }

    /// <summary><c>aspf=s</c>: the same, for the envelope domain.</summary>
    public bool StrictSpf { get; init; }

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

    /// <summary>
    /// Sources whose DKIM signatures verified and were thrown away anyway.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A view over the sources rather than a fourth bucket: every one of these
    /// is already listed as misconfigured, which is what it is. This names the
    /// specific reason, because it is the one an operator gets wrong - the mail
    /// is signed, the key is good, and the mail is still being rejected.
    /// </para>
    /// <para>
    /// Held to a floor. A single forwarded message produces exactly this shape,
    /// and on the live data one domain had six such sources at one message each
    /// sitting above the finding that mattered - a service losing 45 of its 131
    /// messages. The sources below the floor keep their marker in the table;
    /// they just do not get a callout of their own.
    /// </para>
    /// </remarks>
    public IReadOnlyList<DomainSource> SigningUnaligned =>
        [.. Sources.Where(s => s.UnalignedDkim.Count > 0 && s.Failing >= FailuresWorthACallout)
                   .OrderByDescending(s => s.Failing)];

    /// <summary>
    /// How much mail a source has to be losing before it is worth naming on
    /// its own.
    /// </summary>
    /// <remarks>
    /// Deliberately an absolute count rather than a share. A share hides a
    /// service that sends a hundred messages for a domain that sends a hundred
    /// thousand, and that service is exactly the kind whose mail nobody misses
    /// until an invoice does not arrive.
    /// </remarks>
    public const int FailuresWorthACallout = 5;

    /// <summary>
    /// The sub-case where the domain's own <c>adkim=s</c> is what rejects the
    /// signature, and relaxing it would not.
    /// </summary>
    public bool AnyWouldAlignIfRelaxed =>
        SigningUnaligned.Any(s => s.UnalignedDkim.Any(u => u.WouldAlignIfRelaxed));

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

        var policyRow = await PolicyAsync(db, domainId, ct).ConfigureAwait(false);
        var (policy, subPolicy, pct, lastReport) = (policyRow.Policy, policyRow.Sub, policyRow.Pct, policyRow.Last);
        var (messages, passing, overridden) = await TotalsAsync(db, domainId, since, ct).ConfigureAwait(false);
        var sources = await SourcesAsync(db, domainId, since, ct).ConfigureAwait(false);
        var reporters = await ReportersAsync(db, domainId, since, ct).ConfigureAwait(false);

        sources = MarkTheUnaligned(sources, name, policyRow.StrictDkim);

        var detail = new DomainDetail
        {
            Domain = name,
            ClientName = clientName,
            ClientSlug = clientSlug,
            Policy = policy,
            SubdomainPolicy = subPolicy,
            Pct = pct,
            PolicyTarget = target,
            StrictDkim = policyRow.StrictDkim,
            StrictSpf = policyRow.StrictSpf,
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

    private readonly record struct PublishedPolicy(
        string Policy, string Sub, int Pct, DateTimeOffset? Last, bool StrictDkim, bool StrictSpf);

    private static async Task<PublishedPolicy> PolicyAsync(
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
            SELECT policy_p, COALESCE(policy_sp, ''), COALESCE(policy_pct, 100), date_end,
                   COALESCE(policy_adkim, 'r'), COALESCE(policy_aspf, 'r')
            FROM aggregate_reports
            WHERE domain_id = $domain
            ORDER BY date_end DESC, received_at DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$domain", domainId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return new PublishedPolicy("none", "", 100, null, false, false);
        }

        return new PublishedPolicy(
            reader.IsDBNull(0) ? "none" : reader.GetString(0),
            reader.GetString(1),
            reader.GetInt32(2),
            reader.IsDBNull(3) ? null : ParseDate(reader.GetString(3)),
            // Relaxed unless the report says otherwise, which is what RFC 7489
            // defaults to. Guessing strict would invent near misses.
            string.Equals(reader.GetString(4), "s", StringComparison.OrdinalIgnoreCase),
            string.Equals(reader.GetString(5), "s", StringComparison.OrdinalIgnoreCase));
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
                   MAX(r.date_begin),
                   -- Kept apart from the column above, which merges the two
                   -- mechanisms into one "it proved something". Which one
                   -- proved it decides the fix: an unaligned DKIM signature is
                   -- the sender signing the wrong domain, an unaligned SPF pass
                   -- is usually just how a relay works and cannot be fixed the
                   -- same way.
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT
                     CASE WHEN r.dmarc_result = 'fail' AND r.dkim_auth_result = 'pass'
                          THEN r.dkim_domain END), ''), ''),
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT NULLIF(r.spf_domain, '')), ''), ''),
                   -- Signatures on mail that PASSED, which is a different
                   -- question from whether the source passes: a source can pass
                   -- DMARC by some other route while its signatures name
                   -- somebody else entirely.
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT
                     CASE WHEN r.dmarc_result = 'pass' AND r.dkim_auth_result = 'pass'
                          THEN r.dkim_domain END), ''), '')
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
                // Carried as the raw signing domains; the alignment verdict is
                // put on afterwards, where the From domain and the domain's own
                // alignment mode are both in hand.
                UnalignedDkim = [.. Split(reader.IsDBNull(6) ? "" : reader.GetString(6))
                    .Select(d => new UnalignedSignature(d, AlignmentVerdict.Exact, false))],
                EnvelopeDomains = [.. Split(reader.IsDBNull(7) ? "" : reader.GetString(7))],
                DkimOnPassingMail = [.. Split(reader.IsDBNull(8) ? "" : reader.GetString(8))],
            });
        }
        return results;
    }

    private static IEnumerable<string> Split(string concatenated) =>
        concatenated.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => d.TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Works out which of the verified signatures DMARC threw away, and why.
    /// </summary>
    /// <remarks>
    /// Done here rather than in SQL because it needs the From domain and the
    /// published alignment mode together, and because the answer for a
    /// signature that matches exactly is "nothing to say" - a source can fail
    /// DMARC on some messages while signing this domain correctly on others,
    /// and that is a broken signature, not a misaddressed one.
    /// </remarks>
    private static List<DomainSource> MarkTheUnaligned(List<DomainSource> sources, string domain, bool strictDkim)
    {
        // Envelope domains belonging to a service that is already getting this
        // right somewhere. Only from sources with no failures at all - a source
        // that half works is not proof that the vendor can do it - and only
        // where the source actually produced an ALIGNED signature. Passing
        // DMARC is not the same claim: three addresses pass for bmcedc.com on
        // the live data while signing the very domain the failing address
        // signs, and reading those as proof would be a false accusation
        // against a vendor.
        var provenGood = sources
            .Where(s => s.IsClean && s.Messages > 0
                     && s.DkimOnPassingMail.Any(d => Alignment.Aligns(d, domain, strictDkim)))
            .SelectMany(s => s.EnvelopeDomains.Select(e => (Envelope: e, s.SourceIp)))
            // A shared envelope only means "the same service" when the envelope
            // is somebody else's. Every one of the domain's own servers shares
            // the domain's own envelope, and pointing one at another as proof
            // of anything is noise.
            .Where(x => Alignment.Classify(x.Envelope, domain) == AlignmentVerdict.Unrelated)
            .GroupBy(x => x.Envelope, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().SourceIp, StringComparer.Ordinal);

        return
        [
            .. sources.Select(s =>
            {
                var unaligned = s.UnalignedDkim
                    .Select(u => Alignment.Classify(u.Domain, domain))
                    .Zip(s.UnalignedDkim, (verdict, u) => (verdict, u.Domain))
                    .Where(x => x.verdict != AlignmentVerdict.Exact)
                    .Select(x => new UnalignedSignature(
                        x.Domain,
                        x.verdict,
                        WouldAlignIfRelaxed: x.verdict == AlignmentVerdict.Organizational && strictDkim))
                    .ToList();

                var sibling = unaligned.Count == 0
                    ? null
                    : s.EnvelopeDomains
                        .Select(e => provenGood.GetValueOrDefault(e))
                        .FirstOrDefault(ip => ip is not null && !string.Equals(ip, s.SourceIp, StringComparison.Ordinal));

                return s with { UnalignedDkim = unaligned, SameServiceSigningCorrectly = sibling };
            }),
        ];
    }

    private static async Task<List<DomainReporter>> ReportersAsync(
        SqliteConnection db, string domainId, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Who is reporting matters as much as what they say. A domain heard
        // from by one receiver is a domain whose picture is partial, and an
        // operator reading a clean pass rate should be able to see that.
        //
        // Deliberately NOT limited to the window. A reporter that stopped is
        // invisible inside a window that begins after it stopped, which is
        // exactly the case worth seeing, so this is the whole history and the
        // silence is measured against it.
        command.CommandText = """
            SELECT r.org_name,
                   COUNT(DISTINCT r.id),
                   MAX(r.date_end),
                   COALESCE(SUM(rec.message_count), 0)
            FROM aggregate_reports r
            LEFT JOIN aggregate_records rec ON rec.report_id = r.id
            WHERE r.domain_id = $domain
            GROUP BY r.org_name
            ORDER BY COUNT(DISTINCT r.id) DESC
            """;
        command.Parameters.AddWithValue("$domain", domainId);

        var results = new List<DomainReporter>();
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                results.Add(new DomainReporter
                {
                    OrgName = reader.GetString(0),
                    Reports = reader.GetInt32(1),
                    LastReport = reader.IsDBNull(2) ? null : ParseDate(reader.GetString(2)),
                    Messages = reader.GetInt64(3),
                });
            }
        }

        return MarkTheQuietOnes(results);
    }

    /// <summary>A reporter carrying at least this share of the mail is worth missing.</summary>
    /// <remarks>
    /// Below it, silence is ordinary: plenty of receivers send one report when
    /// one message happens to pass through them and are never heard from
    /// again, and flagging those would bury the one that matters.
    /// </remarks>
    public const double SignificantReporterShare = 10.0;

    /// <summary>
    /// How long a reporter has to be silent before it counts as gone.
    /// </summary>
    /// <remarks>
    /// Aggregate reports are daily by convention, so a week and a half of
    /// nothing is well past a missed run or a weekend.
    /// </remarks>
    public const int DaysBeforeAReporterCountsAsQuiet = 10;

    private static List<DomainReporter> MarkTheQuietOnes(List<DomainReporter> reporters)
    {
        var total = reporters.Sum(r => r.Messages);
        if (total == 0) { return reporters; }

        var newest = reporters.Max(r => r.LastReport);
        if (newest is null) { return reporters; }

        var now = DateTimeOffset.UtcNow;

        // Judged against the newest report for THIS domain rather than against
        // the clock, so a database restored from a backup, or an import of an
        // old archive, does not light up every row at once.
        return
        [
            .. reporters.Select(r =>
            {
                var share = Math.Round(r.Messages * 100.0 / total, 1);
                var silent = r.LastReport is null ? (int?)null : (int)(now - r.LastReport.Value).TotalDays;
                var behind = r.LastReport is null ? 0 : (newest.Value - r.LastReport.Value).TotalDays;

                return r with
                {
                    Share = share,
                    DaysSilent = silent,
                    HasGoneQuiet = share >= SignificantReporterShare
                                && behind >= DaysBeforeAReporterCountsAsQuiet,
                };
            }),
        ];
    }

    private static DateTimeOffset? ParseDate(string raw) =>
        DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
            ? new DateTimeOffset(d, TimeSpan.Zero)
            : null;
}
