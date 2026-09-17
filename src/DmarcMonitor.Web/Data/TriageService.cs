using System.Globalization;
using DmarcMonitor.Core.Rollout;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Data;

/// <summary>Where the SQLite file is, so pages can say so when it is empty.</summary>
public sealed record DatabaseInfo(string Path);

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

    /// <summary>When the current policy stage deliberately began.</summary>
    public DateTimeOffset? BaselineStarted { get; init; }

    /// <summary>How long that stage is meant to run before advancing.</summary>
    public int BaselineDays { get; init; } = 14;

    /// <summary>Where the domain is heading, which is not always reject.</summary>
    public string PolicyTarget { get; init; } = "reject";

    public int? DaysAtStage => BaselineStarted is null
        ? null
        : (int)(DateTimeOffset.UtcNow - BaselineStarted.Value).TotalDays;

    /// <summary>Inside a deliberate baseline window that has not finished.</summary>
    public bool InBaseline => DaysAtStage is { } days && days < BaselineDays;

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
              (SELECT MAX(ar.date_end) FROM aggregate_reports ar WHERE ar.domain_id = d.id)  AS last_report,
              d.baseline_started_at,
              d.baseline_days,
              d.policy_target
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
                BaselineStarted = reader.IsDBNull(8) ? null : ParseDate(reader.GetString(8)),
                BaselineDays = reader.IsDBNull(9) ? 14 : reader.GetInt32(9),
                PolicyTarget = reader.IsDBNull(10) ? "reject" : reader.GetString(10),
            };

            // The judgement lives in Core and is unit tested against every
            // combination. Duplicating it here would mean the page could
            // disagree with the tests.
            var verdict = RolloutAssessment.Assess(new DomainState
            {
                Domain = row.Domain,
                Policy = row.Policy,
                PolicyTarget = row.PolicyTarget,
                Messages = row.Messages,
                Passing = row.Passing,
                FailingSources = row.FailingSources,
                LastReport = row.LastReport,
                BaselineStarted = row.BaselineStarted,
                BaselineDays = row.BaselineDays,
            });

            rows.Add(row with { Level = verdict.Level, Headline = verdict.Headline });
        }

        // Worst first, then by how much mail is affected: between two equally
        // urgent domains, the one losing more mail is the one to open.
        return [.. rows
            .OrderByDescending(r => r.Level)
            .ThenByDescending(r => r.Failing)
            .ThenBy(r => r.Domain, StringComparer.Ordinal)];
    }

    private static DateTimeOffset? ParseDate(string raw) =>
        DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
            ? new DateTimeOffset(d, TimeSpan.Zero)
            : null;

}
