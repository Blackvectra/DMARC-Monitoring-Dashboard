using System.Globalization;
using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// Builds a client report for a page or a download.
///
/// Delegates to the same ClientReportBuilder and ClientReportRenderer the CLI
/// uses, so a report downloaded from the browser is byte-for-byte the one
/// `dmarc report` writes. A second rendering path would drift, and the first
/// anybody would hear of it is a client asking why two copies of their month
/// disagree.
/// </summary>
public sealed class ReportUiService(DatabaseInfo database, IConfiguration configuration)
{
    private readonly ClientReportBuilder _builder = new(database.Path);
    private readonly IConfiguration _configuration = configuration;

    /// <summary>How the provider names itself in reports. One place, not one per run.</summary>
    public string ProviderName =>
        IsProviderNameSet ? _configuration["Reporting:ProviderName"]! : "your IT provider";

    /// <summary>
    /// False when reports would go out signed with the placeholder.
    /// </summary>
    /// <remarks>
    /// Worth asking separately rather than comparing the name against the
    /// default string in two places: the page that sends reports needs to warn,
    /// and the settings page needs to say it is unset.
    /// </remarks>
    public bool IsProviderNameSet =>
        _configuration["Reporting:ProviderName"] is { Length: > 0 };

    /// <param name="tenantId">One organization's clients, or null for every organization's.</param>
    public Task<IReadOnlyList<(string Slug, string Name)>> GetClientsAsync(string? tenantId, CancellationToken ct = default) =>
        _builder.GetClientsAsync(tenantId, ct);

    /// <param name="tenantId">
    /// The organization the caller may see. A client outside it is not found,
    /// so a report URL guessed for another organization's customer is a 404.
    /// </param>
    public Task<ClientReport?> BuildAsync(string slug, ReportPeriod period, string? tenantId, CancellationToken ct = default) =>
        _builder.BuildAsync(slug, period, ProviderName, tenantId, ct);

    /// <summary>The months worth offering, newest first, ending with the last complete one.</summary>
    public static IReadOnlyList<(string Value, string Label)> RecentMonths(int count = 12)
    {
        var months = new List<(string, string)>(count + 1);

        var thisMonth = new DateTimeOffset(
            DateTimeOffset.UtcNow.Year, DateTimeOffset.UtcNow.Month, 1, 0, 0, 0, TimeSpan.Zero);

        // The month in progress, named as being in progress.
        //
        // It was left out entirely, and the reasoning was sound as far as it
        // went: a report whose numbers change between two runs in the same
        // week cannot be reconciled against an invoice, so the list started
        // at the month that had ENDED.
        //
        // What that missed is that a new install's data is almost always in
        // the month it is installed. On 22 September the whole list read
        // August back to September 2025, September 2026 was not on it at all,
        // and the first thing anybody saw was "Nothing stored for that month"
        // on a database holding three weeks of reports. A real report was
        // produced for a customer that way, and the only thing it said was
        // that no reports had arrived.
        //
        // So it is offered and labelled, not hidden. "so far" is the whole
        // safeguard: nobody sends a month called "so far" to a customer as a
        // final statement, and everybody wants to look at it.
        months.Add((
            thisMonth.ToString("yyyy-MM", CultureInfo.InvariantCulture),
            thisMonth.ToString("MMMM yyyy", CultureInfo.InvariantCulture) + " (so far)"));

        var month = thisMonth.AddMonths(-1);
        for (var i = 0; i < count; i++, month = month.AddMonths(-1))
        {
            months.Add((
                month.ToString("yyyy-MM", CultureInfo.InvariantCulture),
                month.ToString("MMMM yyyy", CultureInfo.InvariantCulture)));
        }

        return months;
    }

    /// <summary>
    /// The most recent month this client has any report data for, or null.
    /// </summary>
    /// <remarks>
    /// What the month picker should open on. Defaulting to the last complete
    /// month is right for an install that has been collecting for a year and
    /// wrong for every install in its first few weeks - which is every
    /// install somebody is deciding about.
    /// </remarks>
    public Task<string?> LatestMonthWithDataAsync(string slug, string? tenantId, CancellationToken ct = default) =>
        _builder.LatestMonthWithDataAsync(slug, tenantId, ct);

    public static bool TryParseMonth(string? value, out ReportPeriod period)
    {
        if (DateTime.TryParseExact(value, "yyyy-MM", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
        {
            period = ReportPeriod.ForMonth(parsed.Year, parsed.Month);
            return true;
        }

        period = ReportPeriod.MonthEnding(DateTimeOffset.UtcNow);
        return false;
    }
}
