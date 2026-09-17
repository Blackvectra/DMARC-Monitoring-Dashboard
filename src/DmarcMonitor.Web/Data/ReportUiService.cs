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
        _configuration["Reporting:ProviderName"] is { Length: > 0 } name ? name : "your IT provider";

    public Task<IReadOnlyList<(string Slug, string Name)>> GetClientsAsync(CancellationToken ct = default) =>
        _builder.GetClientsAsync(ct);

    public Task<ClientReport?> BuildAsync(string slug, ReportPeriod period, CancellationToken ct = default) =>
        _builder.BuildAsync(slug, period, ProviderName, ct);

    /// <summary>The months worth offering, newest first, ending with the last complete one.</summary>
    public static IReadOnlyList<(string Value, string Label)> RecentMonths(int count = 12)
    {
        var months = new List<(string, string)>(count);

        // Starts at the month that has ENDED. Offering the current one by
        // default invites a report whose numbers change between two runs in
        // the same week, which cannot be reconciled against an invoice.
        var month = new DateTimeOffset(DateTimeOffset.UtcNow.Year, DateTimeOffset.UtcNow.Month, 1, 0, 0, 0, TimeSpan.Zero)
            .AddMonths(-1);

        for (var i = 0; i < count; i++, month = month.AddMonths(-1))
        {
            months.Add((
                month.ToString("yyyy-MM", CultureInfo.InvariantCulture),
                month.ToString("MMMM yyyy", CultureInfo.InvariantCulture)));
        }

        return months;
    }

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
