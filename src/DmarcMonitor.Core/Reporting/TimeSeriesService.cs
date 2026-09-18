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
