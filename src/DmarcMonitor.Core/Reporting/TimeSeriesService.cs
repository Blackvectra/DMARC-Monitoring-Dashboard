using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Reporting;

/// <summary>One day of mail, as the receivers described it.</summary>
public sealed record DayPoint
{
    public required DateOnly Day { get; init; }

    /// <summary>
    /// False when no receiver reported on this day at all.
    /// </summary>
    /// <remarks>
    /// The distinction the whole series exists to keep. A day nobody reported
    /// on is not a day with no mail: receivers miss runs, an <c>rua</c> gets
    /// changed, collection breaks. Drawn as zero it becomes a cliff to the
    /// floor and back, and somebody spends an afternoon looking for an outage
    /// that never happened. Charts break the line across these instead.
    /// </remarks>
    public bool Reported { get; init; }

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing => Messages - Passing;

    /// <summary>What the receiver actually did, as opposed to what it concluded.</summary>
    public long Quarantined { get; init; }
    public long Rejected { get; init; }

    /// <summary>Delivered despite failing: p=none, pct sampling, or an override.</summary>
    public long DeliveredAnyway => Math.Max(0, Failing - Quarantined - Rejected);

    /// <summary>Null on an unreported day, so a chart plots a gap rather than 0%.</summary>
    public double? PassRate =>
        !Reported || Messages == 0 ? null : Math.Round(Passing * 100.0 / Messages, 1);
}

/// <summary>
/// All of a window's mail split three ways, for the dial.
/// </summary>
/// <remarks>
/// <para>
/// The split a mail administrator actually needs, and one a pass rate cannot
/// give: of everything sent as these domains, how much authenticated, how much
/// failed for a reason the receiver itself called expected, and how much
/// failed having proved nothing at all. Only the third is a problem, and on a
/// healthy estate it is the smallest number on the page - which is exactly why
/// it needs its own segment rather than being folded into "failing".
/// </para>
/// </remarks>
public sealed record VolumeBreakdown
{
    /// <summary>Passed DMARC: authenticated and aligned.</summary>
    public long Authenticated { get; init; }

    /// <summary>
    /// Failed, but the receiver recorded why and declined to apply the policy.
    /// </summary>
    /// <remarks>
    /// Forwarding and mailing lists break DKIM signatures as a matter of
    /// course. Counting this against a domain makes a well-run estate look
    /// broken, and chasing it wastes the time that should go on the last
    /// bucket.
    /// </remarks>
    public long Overridden { get; init; }

    /// <summary>
    /// Failed and proved nothing. A service nobody recorded, or somebody
    /// sending as the domain.
    /// </summary>
    public long Unauthenticated { get; init; }

    public long Total => Authenticated + Overridden + Unauthenticated;

    /// <summary>Null rather than 0% when there was no mail to judge.</summary>
    public double? PassRate =>
        Total == 0 ? null : Math.Round(Authenticated * 100.0 / Total, 1);
}

/// <summary>One sending service, and how much of its mail authenticates.</summary>
/// <remarks>
/// Keyed on the domain the mail authenticated FOR - the envelope domain SPF
/// checked, or the signing domain where there is no envelope. That is the
/// closest thing to "which service is this" available from a report alone:
/// naming the service properly needs a reverse lookup on the sending address
/// and a catalogue to match it against, and nothing in this product does that
/// yet. <c>em318306.nrgtechservices.com</c> is SendGrid and
/// <c>bounce.myngp.com</c> is NGP VAN; the report does not say so, and this
/// type does not pretend to know.
/// </remarks>
public sealed record SourceCompliance
{
    public required string Source { get; init; }
    public long Messages { get; init; }

    /// <summary>Share that passed DMARC: authenticated AND aligned.</summary>
    public double DmarcRate { get; init; }

    /// <summary>Share whose SPF check passed, aligned or not.</summary>
    public double SpfRate { get; init; }

    /// <summary>Share whose DKIM signature verified, aligned or not.</summary>
    public double DkimRate { get; init; }

    /// <summary>
    /// True when SPF or DKIM passes far more often than DMARC does.
    /// </summary>
    /// <remarks>
    /// The alignment gap, made visible per service. A row reading SPF 100%,
    /// DKIM 100%, DMARC 2% is not three numbers that disagree - it is a
    /// service authenticating perfectly for its own domain and counting for
    /// nothing, which is the single most misread situation in DMARC.
    /// </remarks>
    public bool AuthenticatesButDoesNotAlign =>
        Math.Max(SpfRate, DkimRate) - DmarcRate >= 20;
}

/// <summary>
/// Mail per day, for the charts.
/// </summary>
/// <remarks>
/// <para>
/// Every figure elsewhere in this product is a total over a window. A total
/// cannot show the shape of a change: a domain that was fine until Tuesday
/// and has been rejecting a third of its mail since reads as "96% passing"
/// for the month, which is true and useless.
/// </para>
/// <para>
/// Buckets are whole UTC days, matching how receivers file aggregate reports.
/// Anything finer invents precision the source data does not have.
/// </para>
/// </remarks>
public sealed class TimeSeriesService(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    /// <summary>The whole estate, one point per day.</summary>
    public Task<IReadOnlyList<DayPoint>> EstateAsync(int days = 30, CancellationToken ct = default) =>
        QueryAsync(null, null, days, ct);

    /// <summary>One domain, one point per day.</summary>
    public Task<IReadOnlyList<DayPoint>> DomainAsync(string domain, int days = 30, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        return QueryAsync(domain.Trim().TrimEnd('.').ToLowerInvariant(), null, days, ct);
    }

    /// <summary>One client's domains together, one point per day.</summary>
    public Task<IReadOnlyList<DayPoint>> ClientAsync(string slug, int days = 30, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);
        return QueryAsync(null, slug.Trim(), days, ct);
    }

    /// <summary>
    /// The window's mail split three ways, for the dial.
    /// </summary>
    /// <param name="domain">One domain, or null for the whole estate.</param>
    public async Task<VolumeBreakdown> BreakdownAsync(
        string? domain = null, int days = 30, CancellationToken ct = default)
    {
        if (days < 1) { throw new ArgumentOutOfRangeException(nameof(days), days, "A window needs at least one day."); }

        var name = string.IsNullOrWhiteSpace(domain) ? null : domain.Trim().TrimEnd('.').ToLowerInvariant();
        var since = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-(days - 1))
            .ToDateTime(TimeOnly.MinValue).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();

        // The override test is scoped to FAILING rows on purpose. Receivers
        // also record an override on mail that passed - Microsoft stamps "SPF
        // ignored due to local policy" on traffic that authenticated perfectly
        // well by DKIM - and counting those here would move a domain's own
        // clean mail out of the authenticated segment.
        command.CommandText = $"""
            SELECT COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass'
                                      AND r.override_reason IS NOT NULL AND r.override_reason <> ''
                                     THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass'
                                      AND (r.override_reason IS NULL OR r.override_reason = '')
                                     THEN r.message_count END), 0)
            FROM aggregate_records r
            {Joins(name, null, "r")}
            WHERE r.date_begin >= $since {Filter(name, null)}
            """;
        Bind(command, name, null, since);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return new VolumeBreakdown(); }

        return new VolumeBreakdown
        {
            Authenticated = reader.GetInt64(0),
            Overridden = reader.GetInt64(1),
            Unauthenticated = reader.GetInt64(2),
        };
    }

    /// <summary>
    /// The services sending this mail, and how much of theirs authenticates.
    /// </summary>
    /// <param name="domain">One domain, or null for the whole estate.</param>
    /// <param name="top">How many to return, busiest first.</param>
    public async Task<IReadOnlyList<SourceCompliance>> SourcesAsync(
        string? domain = null, int days = 30, int top = 8, CancellationToken ct = default)
    {
        if (days < 1) { throw new ArgumentOutOfRangeException(nameof(days), days, "A window needs at least one day."); }
        if (top < 1) { throw new ArgumentOutOfRangeException(nameof(top), top, "Asking for no rows returns an empty panel with nothing to explain it."); }

        var name = string.IsNullOrWhiteSpace(domain) ? null : domain.Trim().TrimEnd('.').ToLowerInvariant();
        var since = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-(days - 1))
            .ToDateTime(TimeOnly.MinValue).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();

        // SPF's domain first, then DKIM's. A service is identified by the
        // envelope it sends under; only where there is none does the signature
        // say who it was. Rows carrying neither are grouped as unattributed
        // rather than dropped: mail nobody can name is worth seeing, and a
        // panel that quietly omits it overstates how well the estate is doing.
        command.CommandText = $"""
            SELECT COALESCE(NULLIF(r.spf_domain, ''), NULLIF(r.dkim_domain, ''), '(not stated)'),
                   COALESCE(SUM(r.message_count), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.spf_auth_result = 'pass' THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dkim_auth_result = 'pass' THEN r.message_count END), 0)
            FROM aggregate_records r
            {Joins(name, null, "r")}
            WHERE r.date_begin >= $since {Filter(name, null)}
            GROUP BY 1
            HAVING SUM(r.message_count) > 0
            ORDER BY SUM(r.message_count) DESC
            LIMIT $top
            """;
        Bind(command, name, null, since);
        command.Parameters.AddWithValue("$top", top);

        var rows = new List<SourceCompliance>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var messages = reader.GetInt64(1);
            if (messages <= 0) { continue; }

            rows.Add(new SourceCompliance
            {
                Source = reader.GetString(0),
                Messages = messages,
                DmarcRate = Math.Round(reader.GetInt64(2) * 100.0 / messages, 1),
                SpfRate = Math.Round(reader.GetInt64(3) * 100.0 / messages, 1),
                DkimRate = Math.Round(reader.GetInt64(4) * 100.0 / messages, 1),
            });
        }

        return rows;
    }

    /// <summary>
    /// How many domains sent mail in the window, and how many did not.
    /// </summary>
    /// <remarks>
    /// A domain nobody sends as is not a domain that is safe: it is a domain
    /// whose DMARC record nobody is watching, and the usual reason an estate
    /// has hundreds of them is that they were registered defensively and
    /// forgotten. Counted rather than charted because the number is the
    /// point.
    /// </remarks>
    public async Task<(int Active, int Inactive)> DomainActivityAsync(
        int days = 30, CancellationToken ct = default)
    {
        if (days < 1) { throw new ArgumentOutOfRangeException(nameof(days), days, "A window needs at least one day."); }

        var since = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-(days - 1))
            .ToDateTime(TimeOnly.MinValue).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT
              (SELECT COUNT(*) FROM domains),
              (SELECT COUNT(DISTINCT r.domain_id)
                 FROM aggregate_records r
                WHERE r.date_begin >= $since AND r.message_count > 0)
            """;
        command.Parameters.AddWithValue("$since", since);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return (0, 0); }

        var all = reader.GetInt32(0);
        var active = reader.GetInt32(1);

        // Clamped because a record can outlive the domain row it pointed at
        // during a delete, and a negative count on a dashboard is worse than a
        // slightly wrong one.
        return (active, Math.Max(0, all - active));
    }

    /// <summary>
    /// Every domain's series at once, for a column of sparklines.
    /// </summary>
    /// <remarks>
    /// One query rather than one per domain. Asked separately, eighteen
    /// domains are eighteen round trips before the page can render a single
    /// row, and that is exactly how the Fix page came to take twelve seconds.
    ///
    /// Reported-day tracking is deliberately per domain: a receiver reporting
    /// on one domain says nothing about whether it reported on another, and
    /// treating the estate's reporting days as every domain's would hide the
    /// case where one domain alone goes silent.
    /// </remarks>
    public async Task<IReadOnlyDictionary<string, IReadOnlyList<DayPoint>>> PerDomainAsync(
        int days = 30, CancellationToken ct = default)
    {
        if (days < 1) { throw new ArgumentOutOfRangeException(nameof(days), days, "A window needs at least one day."); }

        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var first = today.AddDays(-(days - 1));
        var since = first.ToDateTime(TimeOnly.MinValue)
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var reported = new Dictionary<string, HashSet<DateOnly>>(StringComparer.OrdinalIgnoreCase);
        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT DISTINCT d.name, DATE(rep.date_begin)
                FROM aggregate_reports rep
                JOIN domains d ON d.id = rep.domain_id
                WHERE rep.date_begin >= $since
                """;
            command.Parameters.AddWithValue("$since", since);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (reader.IsDBNull(0) || reader.IsDBNull(1)) { continue; }
                if (!DateOnly.TryParse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                {
                    continue;
                }

                if (!reported.TryGetValue(reader.GetString(0), out var set))
                {
                    set = [];
                    reported[reader.GetString(0)] = set;
                }
                set.Add(day);
            }
        }

        var counted = new Dictionary<string, Dictionary<DateOnly, DayPoint>>(StringComparer.OrdinalIgnoreCase);
        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT d.name, DATE(r.date_begin),
                       COALESCE(SUM(r.message_count), 0),
                       COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                       COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.disposition = 'quarantine'
                                         THEN r.message_count END), 0),
                       COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.disposition = 'reject'
                                         THEN r.message_count END), 0)
                FROM aggregate_records r
                JOIN domains d ON d.id = r.domain_id
                WHERE r.date_begin >= $since
                GROUP BY d.name, DATE(r.date_begin)
                """;
            command.Parameters.AddWithValue("$since", since);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (reader.IsDBNull(0) || reader.IsDBNull(1)) { continue; }
                if (!DateOnly.TryParse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
                {
                    continue;
                }

                var name = reader.GetString(0);
                if (!counted.TryGetValue(name, out var byDay))
                {
                    byDay = [];
                    counted[name] = byDay;
                }

                byDay[day] = new DayPoint
                {
                    Day = day,
                    Reported = true,
                    Messages = reader.GetInt64(2),
                    Passing = reader.GetInt64(3),
                    Quarantined = reader.GetInt64(4),
                    Rejected = reader.GetInt64(5),
                };
            }
        }

        var result = new Dictionary<string, IReadOnlyList<DayPoint>>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in reported.Keys.Concat(counted.Keys).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            counted.TryGetValue(name, out var byDay);
            reported.TryGetValue(name, out var days2);

            var points = new List<DayPoint>(days);
            for (var day = first; day <= today; day = day.AddDays(1))
            {
                if (byDay is not null && byDay.TryGetValue(day, out var row))
                {
                    points.Add(row);
                }
                else
                {
                    points.Add(new DayPoint { Day = day, Reported = days2?.Contains(day) == true });
                }
            }
            result[name] = points;
        }

        return result;
    }

    private async Task<IReadOnlyList<DayPoint>> QueryAsync(
        string? domain, string? clientSlug, int days, CancellationToken ct)
    {
        // A window of nothing is a caller bug, not an empty chart: silently
        // returning no points would render a blank panel with no explanation.
        if (days < 1) { throw new ArgumentOutOfRangeException(nameof(days), days, "A window needs at least one day."); }

        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var first = today.AddDays(-(days - 1));
        var since = first.ToDateTime(TimeOnly.MinValue)
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        // Counted from the records, but the days that EXIST come from the
        // reports: a report can arrive covering a day on which the domain sent
        // nothing, and that is a genuine zero rather than a gap. Collapsing
        // the two would lose exactly the distinction this type is for.
        var reported = await ReportedDaysAsync(db, domain, clientSlug, since, ct).ConfigureAwait(false);
        var counted = await CountsAsync(db, domain, clientSlug, since, ct).ConfigureAwait(false);

        var points = new List<DayPoint>(days);
        for (var day = first; day <= today; day = day.AddDays(1))
        {
            if (counted.TryGetValue(day, out var row))
            {
                points.Add(row with { Day = day, Reported = true });
            }
            else
            {
                points.Add(new DayPoint { Day = day, Reported = reported.Contains(day) });
            }
        }

        return points;
    }

    private static async Task<HashSet<DateOnly>> ReportedDaysAsync(
        SqliteConnection db, string? domain, string? clientSlug, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT DISTINCT DATE(rep.date_begin)
            FROM aggregate_reports rep
            {Joins(domain, clientSlug, "rep")}
            WHERE rep.date_begin >= $since {Filter(domain, clientSlug)}
            """;
        Bind(command, domain, clientSlug, since);

        var days = new HashSet<DateOnly>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            if (!reader.IsDBNull(0) && DateOnly.TryParse(
                    reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
            {
                days.Add(day);
            }
        }
        return days;
    }

    private static async Task<Dictionary<DateOnly, DayPoint>> CountsAsync(
        SqliteConnection db, string? domain, string? clientSlug, string since, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Dispositions are counted only on FAILING rows. A receiver stamps
        // "none" on mail that passed as well, and counting those would make
        // every domain look as though most of its mail had been let through
        // despite failing.
        command.CommandText = $"""
            SELECT DATE(r.date_begin),
                   COALESCE(SUM(r.message_count), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.disposition = 'quarantine'
                                     THEN r.message_count END), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result <> 'pass' AND r.disposition = 'reject'
                                     THEN r.message_count END), 0)
            FROM aggregate_records r
            {Joins(domain, clientSlug, "r")}
            WHERE r.date_begin >= $since {Filter(domain, clientSlug)}
            GROUP BY DATE(r.date_begin)
            """;
        Bind(command, domain, clientSlug, since);

        var rows = new Dictionary<DateOnly, DayPoint>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            if (reader.IsDBNull(0) || !DateOnly.TryParse(
                    reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
            {
                continue;
            }

            rows[day] = new DayPoint
            {
                Day = day,
                Reported = true,
                Messages = reader.GetInt64(1),
                Passing = reader.GetInt64(2),
                Quarantined = reader.GetInt64(3),
                Rejected = reader.GetInt64(4),
            };
        }
        return rows;
    }

    /// <summary>
    /// The joins the filter needs, against whichever table is being counted.
    /// </summary>
    /// <remarks>
    /// The alias is this method's own literal, never anything a caller
    /// supplies: the domain and client themselves go in as bound parameters
    /// below. Nothing here interpolates user input into SQL.
    /// </remarks>
    private static string Joins(string? domain, string? clientSlug, string alias) =>
        domain is null && clientSlug is null
            ? ""
            : $"JOIN domains d ON d.id = {alias}.domain_id"
              + (clientSlug is not null ? " JOIN clients c ON c.id = d.client_id" : "");

    private static string Filter(string? domain, string? clientSlug) =>
        (domain is not null ? " AND d.name = $domain" : "")
        + (clientSlug is not null ? " AND c.slug = $slug" : "");

    private static void Bind(SqliteCommand command, string? domain, string? clientSlug, string since)
    {
        command.Parameters.AddWithValue("$since", since);
        if (domain is not null) { command.Parameters.AddWithValue("$domain", domain); }
        if (clientSlug is not null) { command.Parameters.AddWithValue("$slug", clientSlug); }
    }
}
