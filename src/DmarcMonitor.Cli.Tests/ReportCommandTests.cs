using System.Globalization;
using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// The monthly report the command writes.
/// </summary>
public sealed class ReportCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-report-{Guid.NewGuid():N}");
    private string DbPath => Path.Combine(_dir, "dmarc.db");

    public ReportCommandTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    /// <summary>
    /// The PDF is the document a client receives, so it is written whatever
    /// else is asked for. --html used to switch it off: asking for the long
    /// on-screen copy as well quietly lost the one file that gets sent.
    /// </summary>
    [Fact]
    public async Task AskingForHtmlAsWellStillWritesThePdf()
    {
        // Last month, which is over, so the file is named for the month alone.
        // A month still running carries "-so-far"; see ClientReportPdfTests.
        var now = DateTimeOffset.UtcNow;
        var begin = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero).AddMonths(-1).AddDays(9);
        var store = new ReportStore(DbPath);
        await store.InitializeAsync(DatabaseSchema.Sql);

        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>acme.example</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>198.51.100.7</source_ip><count>40</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>acme.example</header_from></identifiers>
                <auth_results><dkim><domain>acme.example</domain><result>pass</result></dkim>
                  <spf><domain>acme.example</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;
        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await store.SaveAggregateAsync(parsed.Report!, xml, null);

        var slug = await store.CreateClientAsync("Acme");
        await store.AssignDomainAsync("acme.example", slug!);

        var output = Path.Combine(_dir, "out");
        var month = begin.ToString("yyyy-MM", CultureInfo.InvariantCulture);

        var exit = await ReportCommand.RunAsync(
            ["--client", slug!, "--month", month, "--html", "--out", output, "--db", DbPath], CancellationToken.None);

        Assert.Equal(0, exit);
        Assert.True(File.Exists(Path.Combine(output, $"{slug}-{month}.pdf")), "no PDF was written");
        Assert.True(File.Exists(Path.Combine(output, $"{slug}-{month}.html")), "no HTML was written");
    }
}
