using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Data;

/// <summary>Where the SQLite file is, so pages can say so when it is empty.</summary>
public sealed record DatabaseInfo(string Path);

/// <summary>How urgent a domain is. Ordering, not decoration.</summary>
public enum TriageLevel
{
    /// <summary>Nothing to do.</summary>
    Fine,

    /// <summary>Worth knowing, not worth interrupting anyone.</summary>
    Watch,

    /// <summary>Mail is being lost, or will be at the next policy step.</summary>
    Act,

    /// <summary>Mail is being lost right now.</summary>
    Urgent,
}

public sealed record DomainTriage
{
    public required string Domain { get; init; }
    public required string ClientName { get; init; }

    public string Policy { get; init; } = "none";
    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }
    public int Sources { get; init; }
    public int FailingSources { get; init; }
    public DateTimeOffset? LastReport { get; init; }

    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);

    public TriageLevel Level { get; init; } = TriageLevel.Fine;

    /// <summary>The single next action, in plain English. Empty when there is none.</summary>
    public string Headline { get; init; } = "";
}

/// <summary>
/// Ranks every domain by what needs doing.
///
/// The prototype's portfolio view AVERAGED a compliance score across domains.
/// At thirteen domains that is actively misleading: one domain at 20 and
/// twelve at 100 averages to 94, which reads as healthy while a customer's
/// mail is on fire. Averages hide exactly the thing an operator opened the
/// page to find.
///
/// So this ranks rather than averages, and every row carries the one next
/// action rather than a number to interpret.
/// </summary>
public sealed class TriageService(ReportStoreConnection connection)
{
    private readonly ReportStoreConnection _connection = connection;

    /// <param name="days">Window to judge on. Long enough to be stable, short enough to be current.</param>
    public async Task<IReadOnlyList<DomainTriage>> GetAsync(int days = 14, CancellationToken ct = default)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = await _connection.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        // Left join so a domain with no reports still appears. A domain that
        // has gone silent is one of the most important things on this page,
        // and an inner join would remove it entirely.
        command.CommandText = """
            SELECT
              d.name,
              c.name,
              COALESCE(SUM(r.message_count), 0)                                              AS messages,
              COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0)   AS passing,
              COUNT(DISTINCT r.source_ip)                                                    AS sources,
              COUNT(DISTINCT CASE WHEN r.dmarc_result = 'fail' THEN r.source_ip END)         AS failing_sources,
              (SELECT ar.policy_p FROM aggregate_reports ar
                WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1)                 AS policy,
              (SELECT MAX(ar.date_end) FROM aggregate_reports ar WHERE ar.domain_id = d.id)  AS last_report
            FROM domains d
            JOIN clients c ON c.id = d.client_id
            LEFT JOIN aggregate_records r
                   ON r.domain_id = d.id AND r.date_begin >= $since
            WHERE d.is_active = 1
            GROUP BY d.id, d.name, c.name
            """;
        command.Parameters.AddWithValue("$since", since);

        var rows = new List<DomainTriage>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var messages = reader.GetInt64(2);
            var passing = reader.GetInt64(3);
            var policy = reader.IsDBNull(6) ? "none" : reader.GetString(6);

            DateTimeOffset? lastReport = null;
            if (!reader.IsDBNull(7) &&
                DateTime.TryParse(reader.GetString(7), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                lastReport = new DateTimeOffset(parsed, TimeSpan.Zero);
            }

            var row = new DomainTriage
            {
                Domain = reader.GetString(0),
                ClientName = reader.GetString(1),
                Messages = messages,
                Passing = passing,
                Failing = messages - passing,
                Sources = reader.GetInt32(4),
                FailingSources = reader.GetInt32(5),
                Policy = policy,
                LastReport = lastReport,
            };

            rows.Add(Judge(row, days));
        }

        // Worst first, then by how much mail is affected: between two equally
        // urgent domains, the one losing more mail is the one to open.
        return [.. rows
            .OrderByDescending(r => r.Level)
            .ThenByDescending(r => r.Failing)
            .ThenBy(r => r.Domain, StringComparer.Ordinal)];
    }

    /// <summary>
    /// Decides the level and the one next action.
    /// </summary>
    /// <remarks>
    /// Ordered so the worst true statement wins. Mail being refused right now
    /// outranks a domain that is merely not yet enforcing, and both outrank a
    /// clean domain with a note about coverage.
    /// </remarks>
    private static DomainTriage Judge(DomainTriage row, int days)
    {
        var enforcing = row.Policy is "reject" or "quarantine";
        var rate = row.PassRate;

        // Silence is the quiet failure. A domain that was reporting and has
        // stopped usually means the record was changed or removed, and nothing
        // else on this page would show it.
        if (row.LastReport is null)
        {
            return row with
            {
                Level = TriageLevel.Watch,
                Headline = "No reports yet. Check the DMARC record is published with a rua address.",
            };
        }

        var silentFor = DateTimeOffset.UtcNow - row.LastReport.Value;
        if (silentFor > TimeSpan.FromDays(3))
        {
            return row with
            {
                Level = TriageLevel.Act,
                Headline = $"No reports for {(int)silentFor.TotalDays} days. The DMARC record may have been changed or removed.",
            };
        }

        // Enforcing plus failures means real mail is being refused or junked
        // right now. This is the only thing worth interrupting someone for.
        if (enforcing && rate < 95 && row.Failing > 0)
        {
            return row with
            {
                Level = TriageLevel.Urgent,
                Headline = $"p={row.Policy} with {rate}% passing. {row.Failing:N0} messages were "
                         + (row.Policy == "reject" ? "refused" : "sent to junk")
                         + $" in the last {days} days, across {row.FailingSources} source(s).",
            };
        }

        // Not enforcing and failures present: nothing is lost yet, but
        // enforcing today would lose it.
        if (!enforcing && row.Failing > 0)
        {
            return row with
            {
                Level = rate < 90 ? TriageLevel.Act : TriageLevel.Watch,
                Headline = $"p=none, {rate}% passing. Enforcing today would lose {row.Failing:N0} messages "
                         + $"from {row.FailingSources} source(s). Fix those first.",
            };
        }

        if (!enforcing)
        {
            return row with
            {
                Level = TriageLevel.Act,
                Headline = "p=none with everything authenticating. Ready to move to quarantine.",
            };
        }

        if (row.Policy == "quarantine")
        {
            return row with
            {
                Level = TriageLevel.Watch,
                Headline = "Quarantining cleanly. Ready to move to reject.",
            };
        }

        return row with { Level = TriageLevel.Fine, Headline = "" };
    }
}
