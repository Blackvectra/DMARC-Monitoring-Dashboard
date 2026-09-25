using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// Assembles a client's monthly report from stored data.
///
/// Every figure comes from the database, including "what we did", which is
/// read from the DNS change audit trail rather than typed by hand. An MSP who
/// has to remember what they changed for a client six weeks ago will either
/// leave the section out or overstate it, and both are worse than a short,
/// accurate list.
/// </summary>
/// <param name="clock">
/// Today, for a month still in progress. Defaults to the system clock.
/// </param>
public sealed class ClientReportBuilder(string databasePath, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    /// <param name="tenantId">
    /// The organization the caller may see, or null for any. A client of
    /// another organization is reported as not found.
    /// </param>
    public async Task<ClientReport?> BuildAsync(
        string clientSlug, ReportPeriod period, string providerName = ClientReport.UnnamedProvider, string? tenantId = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);
        ArgumentNullException.ThrowIfNull(period);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var client = await GetClientAsync(db, clientSlug, tenantId, ct).ConfigureAwait(false);
        if (client is null) { return null; }

        var (clientId, clientName) = client.Value;

        // The organization's own name and look win over whatever the caller
        // was configured with: NextLayerSec's reports say NextLayerSec even
        // on an install whose default provider name is NRG's.
        var brand = await GetBrandAsync(db, clientId, ct).ConfigureAwait(false);
        if (brand.ProviderName is { Length: > 0 }) { providerName = brand.ProviderName; }

        var domains = await GetDomainHealthAsync(db, clientId, period, ct).ConfigureAwait(false);
        var sources = await GetSourcesAsync(db, clientId, period, ct).ConfigureAwait(false);
        sources.AddRange(await GetRetiredAsync(db, clientId, period, sources, ct).ConfigureAwait(false));
        var changes = await GetChangesAsync(db, clientId, period, ct).ConfigureAwait(false);
        var current = await GetTotalsAsync(db, clientId, period.Start, period.End, ct).ConfigureAwait(false);
        var previous = await GetTotalsAsync(db, clientId, period.PreviousStart, period.PreviousEnd, ct).ConfigureAwait(false);
        // A month still running is covered up to yesterday: today's reports
        // have not been sent yet, and the days after it have not happened.
        // Counted as unreported, they told a client on the 24th that
        // receivers had missed sixteen days of thirty.
        var today = DateOnly.FromDateTime(_clock.GetUtcNow().UtcDateTime);
        DateOnly? through = DateOnly.FromDateTime(period.End.UtcDateTime) >= today ? today.AddDays(-1) : null;
        var daily = await GetDailyAsync(db, clientId, period, through, ct).ConfigureAwait(false);

        return new ClientReport
        {
            Daily = daily,
            Through = through is null || daily.Count == 0 ? null : daily[^1].Day,
            ClientName = clientName,
            ProviderName = providerName,
            BrandColor = brand.Color,
            BrandLogo = brand.Logo,
            ContactBlock = brand.Contact,
            Period = period,
            Domains = domains,
            Sources = sources,
            Changes = changes,
            Messages = current.Messages,
            Passing = current.Passing,
            Failing = current.Messages - current.Passing,
            OverriddenMessages = current.Overridden,
            PreviousMessages = previous.Messages,
            PreviousPassing = previous.Passing,
        };
    }

    /// <summary>Every client that could be reported on, for a "generate all" run.</summary>
    /// <param name="tenantId">One organization's, or null for every organization's.</param>
    public async Task<IReadOnlyList<(string Slug, string Name)>> GetClientsAsync(string? tenantId = null, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText =
            "SELECT slug, name FROM clients WHERE deleted_at IS NULL AND ($tenant IS NULL OR tenant_id = $tenant) ORDER BY name";
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        var results = new List<(string, string)>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add((reader.GetString(0), reader.GetString(1)));
        }
        return results;
    }

    /// <summary>
    /// The most recent month this client has report data for, as yyyy-MM, or
    /// null when it has none at all.
    /// </summary>
    /// <remarks>
    /// So a month picker can open on a month with something in it. Scoped by
    /// tenant like every other read here: a month learned from another
    /// organization's data would be a small leak, and a silly one to make in
    /// a convenience.
    /// </remarks>
    public async Task<string?> LatestMonthWithDataAsync(
        string slug, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT MAX(substr(r.date_begin, 1, 7))
            FROM aggregate_records r
            JOIN clients c ON c.id = r.client_id
            WHERE c.slug = $slug
              AND c.deleted_at IS NULL
              AND ($tenant IS NULL OR r.tenant_id = $tenant)
            """;
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        var value = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);

        return value is string month && month.Length == 7 ? month : null;
    }

    /// <summary>How the client's organization presents itself, all optional.</summary>
    private static async Task<(string? ProviderName, string? Color, string? Logo, string? Contact)> GetBrandAsync(
        SqliteConnection db, string clientId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT t.provider_name, t.brand_primary_color, t.brand_logo, t.brand_contact_block
            FROM clients c JOIN tenants t ON t.id = c.tenant_id
            WHERE c.id = $client LIMIT 1
            """;
        command.Parameters.AddWithValue("$client", clientId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return (null, null, null, null); }

        string? At(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
        return (At(0), At(1), At(2), At(3));
    }

    private static async Task<(string Id, string Name)?> GetClientAsync(
        SqliteConnection db, string slug, string? tenantId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText =
            "SELECT id, name FROM clients WHERE slug = $slug AND deleted_at IS NULL AND ($tenant IS NULL OR tenant_id = $tenant) LIMIT 1";
        command.Parameters.AddWithValue("$slug", slug);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }
        return (reader.GetString(0), reader.GetString(1));
    }

    private static async Task<(long Messages, long Passing, long Overridden)> GetTotalsAsync(
        SqliteConnection db, string clientId, DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT COALESCE(SUM(message_count), 0),
                   COALESCE(SUM(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0),
                   -- Forwarded and receiver-overridden FAILURES are counted
                   -- here and left out of the source tables on purpose, so the
                   -- tables sum to less than this. Carried alongside so the
                   -- report can say so rather than leaving a client to notice
                   -- the arithmetic not working.
                   --
                   -- Failures only: a receiver also records an override on
                   -- mail that PASSED ("SPF ignored due to local policy" on
                   -- DKIM-authenticated traffic), and counting that as left
                   -- out took a client's own clean mail out of its report.
                   --
                   -- And never sampled_out. Under pct=25 a receiver tags the
                   -- three quarters of failing mail it let through with
                   -- exactly that reason, and it was being filed here as
                   -- "handled by the receiver" - so during the one rollout
                   -- step where forgeries are still landing, three quarters
                   -- of them vanished from the threat table and were
                   -- described to the client as mailing-list traffic.
                   COALESCE(SUM(CASE WHEN dmarc_result <> 'pass'
                                      AND override_reason IS NOT NULL AND override_reason <> ''
                                      AND override_reason <> 'sampled_out'
                                     THEN message_count END), 0)
            FROM aggregate_records
            WHERE client_id = $client AND date_begin >= $from AND date_begin <= $to
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(from));
        command.Parameters.AddWithValue("$to", Iso(to));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return (0, 0, 0); }
        return (reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
    }

    /// <summary>
    /// One point per day of the period, for the chart in the report.
    /// </summary>
    /// <remarks>
    /// Scoped to the reported period rather than to a rolling window, because
    /// a client reconciles this against an invoice and the two have to cover
    /// the same days.
    ///
    /// Days nobody reported on stay marked as such. Drawn as zero they become
    /// a cliff to the floor and back, and the client asks why their mail
    /// stopped on a day it did not.
    /// </remarks>
    private static async Task<List<DayPoint>> GetDailyAsync(
        SqliteConnection db, string clientId, ReportPeriod period, DateOnly? through, CancellationToken ct)
    {
        var reported = new HashSet<DateOnly>();
        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT DISTINCT DATE(date_begin)
                FROM aggregate_reports
                WHERE client_id = $client AND date_begin >= $from AND date_begin <= $to
                """;
            command.Parameters.AddWithValue("$client", clientId);
            command.Parameters.AddWithValue("$from", Iso(period.Start));
            command.Parameters.AddWithValue("$to", Iso(period.End));

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (!reader.IsDBNull(0) && DateOnly.TryParse(
                        reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                {
                    reported.Add(day);
                }
            }
        }

        var counted = new Dictionary<DateOnly, DayPoint>();
        await using (var command = db.CreateCommand())
        {
            // Dispositions on failing rows only: a receiver stamps "none" on
            // mail that passed as well, and counting those would tell a client
            // most of their mail was let through despite failing.
            command.CommandText = """
                SELECT DATE(date_begin),
                       COALESCE(SUM(message_count), 0),
                       COALESCE(SUM(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0),
                       COALESCE(SUM(CASE WHEN dmarc_result <> 'pass' AND disposition = 'quarantine'
                                         THEN message_count END), 0),
                       COALESCE(SUM(CASE WHEN dmarc_result <> 'pass' AND disposition = 'reject'
                                         THEN message_count END), 0)
                FROM aggregate_records
                WHERE client_id = $client AND date_begin >= $from AND date_begin <= $to
                GROUP BY DATE(date_begin)
                """;
            command.Parameters.AddWithValue("$client", clientId);
            command.Parameters.AddWithValue("$from", Iso(period.Start));
            command.Parameters.AddWithValue("$to", Iso(period.End));

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (reader.IsDBNull(0) || !DateOnly.TryParse(
                        reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                {
                    continue;
                }

                counted[day] = new DayPoint
                {
                    Day = day,
                    Reported = true,
                    Messages = reader.GetInt64(1),
                    Passing = reader.GetInt64(2),
                    Quarantined = reader.GetInt64(3),
                    Rejected = reader.GetInt64(4),
                };
            }
        }

        var points = new List<DayPoint>();
        var first = DateOnly.FromDateTime(period.Start.UtcDateTime);
        var last = DateOnly.FromDateTime(period.End.UtcDateTime);
        if (through is { } cut)
        {
            // Never before a day that was reported on: a receiver that has
            // already sent today's report has told us about today.
            var latest = reported.Concat(counted.Keys).DefaultIfEmpty(cut).Max();
            last = cut > latest ? cut : latest;
        }

        for (var day = first; day <= last; day = day.AddDays(1))
        {
            points.Add(counted.TryGetValue(day, out var row)
                ? row
                : new DayPoint { Day = day, Reported = reported.Contains(day) });
        }

        return points;
    }

    private static async Task<List<ReportDomainHealth>> GetDomainHealthAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Left join so a domain with no traffic still appears. A client's
        // domain that sent nothing is worth saying out loud, not omitting.
        command.CommandText = """
            SELECT d.name,
                   COALESCE(SUM(r.message_count), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                   -- The policy AS AT THE END OF THE PERIOD, not today's.
                   -- Without the date bound a report for May describes the
                   -- policy in September: regenerate an old month after a
                   -- domain has advanced and it claims the domain was already
                   -- protected when it was not. A report is a statement about
                   -- a period and must not borrow facts from after it.
                   (SELECT ar.policy_p    FROM aggregate_reports ar WHERE ar.domain_id = d.id AND ar.date_end <= $to ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_sp   FROM aggregate_reports ar WHERE ar.domain_id = d.id AND ar.date_end <= $to ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_pct  FROM aggregate_reports ar WHERE ar.domain_id = d.id AND ar.date_end <= $to ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_adkim FROM aggregate_reports ar WHERE ar.domain_id = d.id AND ar.date_end <= $to ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT t.policy_mode  FROM tls_reports t WHERE t.domain_id = d.id AND t.date_end <= $to ORDER BY t.date_end DESC LIMIT 1),
                   -- ALIGNED, which is a different number from "SPF passed".
                   -- A vendor passes SPF for its own envelope domain on every
                   -- message; that is the vendor proving it is the vendor. The
                   -- domain here is the customer's, so this counts only the
                   -- mail where the check was about them - exactly the
                   -- distinction a client is never shown and needs.
                   COALESCE(SUM(CASE WHEN r.spf_auth_result = 'pass'
                                      AND (LOWER(r.spf_domain) = LOWER(d.name)
                                           OR LOWER(r.spf_domain) LIKE '%.' || LOWER(d.name))
                                     THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dkim_auth_result = 'pass'
                                      AND (LOWER(r.dkim_domain) = LOWER(d.name)
                                           OR LOWER(r.dkim_domain) LIKE '%.' || LOWER(d.name))
                                     THEN r.message_count END), 0),
                   COUNT(DISTINCT CASE WHEN r.dmarc_result <> 'pass' THEN r.source_ip END),
                   -- Failures from addresses that never authenticated for
                   -- this client in the period: not once passed DMARC, not
                   -- once proved themselves for any domain. That is forged
                   -- mail, and it is not the domain's own. Judged against
                   -- the total, a domain under a spoofing run read as
                   -- "losing 700 of its own messages - raising a policy now
                   -- would stop them", which told the one client who most
                   -- needed to enforce not to.
                   COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass'
                                      AND r.source_ip NOT IN (
                                          SELECT a.source_ip FROM aggregate_records a
                                          WHERE a.client_id = $client
                                            AND a.date_begin >= $from AND a.date_begin <= $to
                                            AND (a.dmarc_result = 'pass'
                                                 OR a.spf_auth_result = 'pass'
                                                 OR a.dkim_auth_result = 'pass'))
                                     THEN r.message_count END), 0)
            FROM domains d
            LEFT JOIN aggregate_records r
                   ON r.domain_id = d.id AND r.date_begin >= $from AND r.date_begin <= $to
            WHERE d.client_id = $client AND d.deleted_at IS NULL
            GROUP BY d.id, d.name
            ORDER BY d.name
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportDomainHealth>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new ReportDomainHealth
            {
                Domain = reader.GetString(0),
                Messages = reader.GetInt64(1),
                Passing = reader.GetInt64(2),
                // Null means no report reached us at or before this period,
                // so nothing is known about the policy then. Defaulting to
                // "none" would assert the domain was unprotected, which is a
                // claim rather than an absence.
                PolicyKnown = !reader.IsDBNull(3),
                Policy = reader.IsDBNull(3) ? "none" : reader.GetString(3),
                SubdomainPolicy = reader.IsDBNull(4) ? "" : reader.GetString(4),
                Pct = reader.IsDBNull(5) ? 100 : reader.GetInt32(5),
                StrictAlignment = !reader.IsDBNull(6) && reader.GetString(6) == "s",
                MtaStsMode = reader.IsDBNull(7) ? "" : reader.GetString(7),
                SpfAligned = reader.GetInt64(8),
                DkimAligned = reader.GetInt64(9),
                FailingSources = reader.GetInt32(10),
                Forged = reader.GetInt64(11),
            });
        }
        return results;
    }

    private static async Task<List<ReportSource>> GetSourcesAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        // source_names arrived in migration 0015 and is a cache, so a database
        // that has not been upgraded simply has no names. Reporting is a read
        // path and must not fail on one, the way the changes query already
        // does not fail on a remediation table nobody has written to.
        var name = await TableExistsAsync(db, "source_names", ct).ConfigureAwait(false)
            ? "(SELECT n.reverse_name FROM source_names n WHERE n.ip = r.source_ip)"
            : "NULL";

        await using var command = db.CreateCommand();

        // The correlated subquery counts OTHER clients the same source was
        // seen failing against. That is the part of this report no
        // single-tenant tool can produce, and it belongs in front of the
        // client rather than only in the operator's console.
        // Interpolated with $$ so the SQL's own $client and $from stay
        // literal and only {{name}} is substituted.
        command.CommandText = $$"""
            SELECT r.source_ip,
                   SUM(r.message_count),
                   SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count ELSE 0 END),
                   GROUP_CONCAT(DISTINCT d.name),
                   -- Only the FAILING rows. This value decides whether the
                   -- client is told "a service of yours needs correcting" or
                   -- "somebody sent mail as you", so it has to describe the
                   -- mail that failed, not the mail that worked. Taken across
                   -- every row, a source that authenticates legitimately most
                   -- of the time and fails once with no authentication at all
                   -- is labeled a misconfigured service of the client's own,
                   -- and the one message that was actually unprovable
                   -- disappears into a maintenance note.
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT
                     CASE WHEN r.dmarc_result = 'fail' AND r.dkim_auth_result = 'pass' THEN r.dkim_domain
                          WHEN r.dmarc_result = 'fail' AND r.spf_auth_result  = 'pass' THEN r.spf_domain END), ''), ''),
                   (SELECT COUNT(DISTINCT o.client_id)
                      FROM aggregate_records o
                     WHERE o.source_ip = r.source_ip
                       AND o.client_id <> $client
                       AND o.dmarc_result = 'fail'),
                   -- What the address reverses to, so a client is not handed
                   -- a row of digits and asked whether they recognize it.
                   -- Nobody recognizes an address. A correlated subquery
                   -- rather than a join, because source_names is a cache that
                   -- may not have been filled - a LEFT JOIN would do as well
                   -- and this keeps the grouping above untouched.
                   {{name}},
                   -- The raw checks, and then the failures split by cause.
                   -- "1,204 messages failed" is a number to worry about;
                   -- "1,100 are a service signing as itself, 90 are
                   -- forwarding, 14 are nobody we can account for" is three
                   -- different afternoons, two of which belong to somebody
                   -- else.
                   SUM(CASE WHEN r.spf_auth_result  = 'pass' THEN r.message_count ELSE 0 END),
                   SUM(CASE WHEN r.dkim_auth_result = 'pass' THEN r.message_count ELSE 0 END),
                   -- Mutually exclusive, deliberately. A message that passed
                   -- both checks without aligning counted in both rows, so the
                   -- causes added up to more mail than failed: 9 + 6 where the
                   -- truth was 4 + 1 + 5. A client adds up a column.
                   SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.spf_auth_result = 'pass'
                             AND COALESCE(r.dkim_auth_result, '') <> 'pass'
                            THEN r.message_count ELSE 0 END),
                   SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.dkim_auth_result = 'pass'
                             AND COALESCE(r.spf_auth_result, '') <> 'pass'
                            THEN r.message_count ELSE 0 END),
                   SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.spf_auth_result = 'pass'
                             AND r.dkim_auth_result = 'pass'
                            THEN r.message_count ELSE 0 END),
                   SUM(CASE WHEN r.dmarc_result <> 'pass'
                             AND COALESCE(r.spf_auth_result, '')  <> 'pass'
                             AND COALESCE(r.dkim_auth_result, '') <> 'pass'
                            THEN r.message_count ELSE 0 END)
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE r.client_id = $client AND r.date_begin >= $from AND r.date_begin <= $to
              -- Overridden FAILURES only; see GetTotalsAsync. Mail that passed
              -- and merely carried a receiver note is the client's own mail
              -- and belongs in the table.
              AND NOT (r.dmarc_result <> 'pass'
                       AND r.override_reason IS NOT NULL AND r.override_reason <> ''
                       AND r.override_reason <> 'sampled_out')
            GROUP BY r.source_ip
            ORDER BY SUM(r.message_count) DESC
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var messages = reader.GetInt64(1);
            var passing = reader.GetInt64(2);

            results.Add(new ReportSource
            {
                SourceIp = reader.GetString(0),
                Messages = messages,
                Passing = passing,
                Failing = messages - passing,
                Domains = reader.IsDBNull(3) ? [] : [.. reader.GetString(3).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
                AuthenticatedFor = reader.IsDBNull(4) ? "" : reader.GetString(4),
                OtherClientsAffected = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
                ReverseName = reader.IsDBNull(6) ? "" : reader.GetString(6),
                SpfPass = reader.GetInt64(7),
                DkimPass = reader.GetInt64(8),
                FailedSpfNotAligned = reader.GetInt64(9),
                FailedDkimNotAligned = reader.GetInt64(10),
                FailedBothNotAligned = reader.GetInt64(11),
                FailedBoth = reader.GetInt64(12),
            });
        }
        return results;
    }

    /// <summary>
    /// Sources that sent last period and not this one.
    /// </summary>
    /// <remarks>
    /// Not a failure, and worth a line anyway: either a service was retired
    /// and is still authorized to send as the client, or something stopped
    /// working quietly and nobody noticed because nothing failed - it simply
    /// stopped. A report that only lists what sent mail cannot say either.
    ///
    /// Carried with no message count, because they sent none. Every list that
    /// counts mail excludes them by that; see
    /// <see cref="ClientReport.LegitimateSources"/>.
    /// </remarks>
    private static async Task<List<ReportSource>> GetRetiredAsync(
        SqliteConnection db, string clientId, ReportPeriod period,
        List<ReportSource> current, CancellationToken ct)
    {
        var seen = new HashSet<string>(current.Select(s => s.SourceIp), StringComparer.OrdinalIgnoreCase);

        var name = await TableExistsAsync(db, "source_names", ct).ConfigureAwait(false)
            ? "(SELECT n.reverse_name FROM source_names n WHERE n.ip = r.source_ip)"
            : "NULL";

        await using var command = db.CreateCommand();
        command.CommandText = $$"""
            SELECT r.source_ip, SUM(r.message_count), GROUP_CONCAT(DISTINCT d.name), {{name}}
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE r.client_id = $client AND r.date_begin >= $from AND r.date_begin <= $to
            GROUP BY r.source_ip
            -- A single message last period is noise rather than a retired
            -- service, and a report listing every one-off would bury the
            -- three that matter.
            HAVING SUM(r.message_count) >= 10
            ORDER BY SUM(r.message_count) DESC
            LIMIT 25
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.PreviousStart));
        command.Parameters.AddWithValue("$to", Iso(period.PreviousEnd));

        var results = new List<ReportSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var ip = reader.GetString(0);
            if (seen.Contains(ip)) { continue; }

            results.Add(new ReportSource
            {
                SourceIp = ip,
                Retired = true,
                Domains = reader.IsDBNull(2) ? [] : [.. reader.GetString(2).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
                ReverseName = reader.IsDBNull(3) ? "" : reader.GetString(3),
            });
        }

        return results;
    }

    /// <summary>
    /// What was actually changed for this client, from the audit trail.
    /// </summary>
    /// <remarks>
    /// Rolled-back changes are included and labeled. Hiding them would make
    /// the report a sales document rather than a record: a change that was
    /// applied and then reverted is exactly the kind of thing a client should
    /// hear from their provider rather than discover.
    /// </remarks>
    private static async Task<List<ReportChange>> GetChangesAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        // The remediation tables exist in the schema but are written by the
        // apply path, which may not have run. A client with no changes is
        // normal, not an error.
        if (!await TableExistsAsync(db, "dns_changes", ct).ConfigureAwait(false)) { return []; }

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT record_name, record_type, previous_value, new_value, reason, applied_at, rolled_back_at
            FROM dns_changes
            WHERE client_id = $client AND applied_at >= $from AND applied_at <= $to
            ORDER BY applied_at
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportChange>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            DateTimeOffset appliedAt = default;
            if (!reader.IsDBNull(5) &&
                DateTime.TryParse(reader.GetString(5), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                appliedAt = new DateTimeOffset(parsed, TimeSpan.Zero);
            }

            results.Add(new ReportChange
            {
                RecordName = reader.GetString(0),
                RecordType = reader.GetString(1),
                PreviousValue = reader.IsDBNull(2) ? "" : reader.GetString(2),
                NewValue = reader.IsDBNull(3) ? "" : reader.GetString(3),
                Reason = reader.IsDBNull(4) ? "" : reader.GetString(4),
                AppliedAt = appliedAt,
                WasRolledBack = !reader.IsDBNull(6),
            });
        }
        return results;
    }

    private static async Task<bool> TableExistsAsync(SqliteConnection db, string name, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name";
        command.Parameters.AddWithValue("$name", name);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
