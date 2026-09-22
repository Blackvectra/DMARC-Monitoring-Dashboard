using System.Globalization;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// How long each kind of report is kept.
/// </summary>
/// <remarks>
/// <para>
/// Two classes rather than one number, because they carry different things.
/// Aggregate reports are counts: how many messages came from an address and
/// what happened to them. Forensic reports are copies of real messages -
/// subject lines, message ids, the headers of somebody's mail - and keeping
/// those indefinitely turns a monitoring tool into a mail archive nobody
/// agreed to.
/// </para>
/// <para>
/// The schema has assumed a retention window since it was written and nothing
/// ever enforced one, so both tables grew without bound.
/// </para>
/// </remarks>
public sealed record RetentionPolicy
{
    /// <summary>
    /// Days of aggregate data kept. Thirteen months by default.
    /// </summary>
    /// <remarks>
    /// Thirteen rather than twelve on purpose: a client's monthly report is
    /// most useful beside the same month a year earlier, and twelve months
    /// exactly means that comparison is gone the day it is wanted.
    /// </remarks>
    public int AggregateDays { get; init; } = 400;

    /// <summary>
    /// Days of forensic data kept. Thirty by default, and deliberately the
    /// shortest window here.
    /// </summary>
    /// <remarks>
    /// These hold other people's message headers. Thirty days is long enough
    /// to investigate something that happened last month and short enough that
    /// the product is not quietly accumulating a year of somebody's mail.
    /// </remarks>
    public int ForensicDays { get; init; } = 30;

    /// <summary>The shortest window that may be configured.</summary>
    /// <remarks>
    /// A floor rather than a preference. Receivers report on a day's mail up to
    /// a day or two later, so a window under a week would delete reports about
    /// mail that is still arriving, and the domain would read as quiet.
    /// </remarks>
    public const int MinimumDays = 7;

    /// <summary>What is wrong with this policy, or empty when nothing is.</summary>
    public IReadOnlyList<string> Problems
    {
        get
        {
            var problems = new List<string>();

            if (AggregateDays < MinimumDays)
            {
                problems.Add($"aggregate retention is {AggregateDays} days and the shortest allowed is "
                           + $"{MinimumDays}: receivers report a day or two late, so anything shorter "
                           + "deletes reports about mail that is still arriving");
            }

            if (ForensicDays < MinimumDays)
            {
                problems.Add($"forensic retention is {ForensicDays} days and the shortest allowed is "
                           + $"{MinimumDays}");
            }

            if (ForensicDays > AggregateDays)
            {
                problems.Add($"forensic retention ({ForensicDays} days) is longer than aggregate "
                           + $"({AggregateDays}): forensic reports hold real message headers and should "
                           + "never be the thing kept longest");
            }

            return problems;
        }
    }

    public bool IsValid => Problems.Count == 0;

    /// <summary>The cutoff for each class, as the database stores dates.</summary>
    public string AggregateCutoff(DateTimeOffset now) => Cutoff(now, AggregateDays);

    public string ForensicCutoff(DateTimeOffset now) => Cutoff(now, ForensicDays);

    private static string Cutoff(DateTimeOffset now, int days) =>
        now.AddDays(-Math.Max(MinimumDays, days))
            .UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>One line for a settings page or a log entry.</summary>
    public override string ToString() =>
        $"aggregate {AggregateDays} days, forensic {ForensicDays} days";
}

/// <summary>What a prune did, or would do.</summary>
/// <param name="AggregateReports">Whole reports removed.</param>
/// <param name="AggregateRecords">Rows inside them.</param>
/// <param name="ForensicReports">Forensic reports removed.</param>
/// <param name="TlsReports">TLS reports removed, on the aggregate window.</param>
/// <param name="Applied">False for a dry run.</param>
public sealed record PruneResult(
    int AggregateReports,
    int AggregateRecords,
    int ForensicReports,
    int TlsReports,
    bool Applied)
{
    public int Total => AggregateReports + ForensicReports + TlsReports;

    public bool NothingToDo => Total == 0;

    /// <summary>What happened, for the operator and for the audit log.</summary>
    public string Describe() =>
        NothingToDo
            ? "nothing is old enough to remove"
            : $"{(Applied ? "removed" : "would remove")} {AggregateReports:N0} aggregate report(s) "
              + $"({AggregateRecords:N0} row(s)), {ForensicReports:N0} forensic report(s), "
              + $"{TlsReports:N0} TLS report(s)";
}
