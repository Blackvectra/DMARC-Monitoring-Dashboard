using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Assembling a client report from stored data.
///
/// The judgement being tested is the one the whole product turns on: telling a
/// misconfigured service of the client's own apart from somebody sending as
/// the client. Getting it backwards sends an operator to fix a mail service
/// that is fine while an impersonation attempt is filed as maintenance.
/// </summary>
public sealed class ClientReportBuilderTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-report-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public ClientReportBuilderTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitialiseAsync(File.ReadAllText(FindSchema())).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static string FindSchema()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "db", "schema.sql");
            if (File.Exists(candidate)) { return candidate; }
        }
        throw new FileNotFoundException("Could not find db/schema.sql from the test output directory.");
    }

    /// <summary>
    /// A report with hand-written rows, so a source's mixture of passing and
    /// failing traffic can be set exactly.
    /// </summary>
    private static string Xml(string domain, string policy, params string[] rows) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>test.example</org_name>
            <email>dmarc@test.example</email>
            <report_id>{Guid.NewGuid():N}</report_id>
            <date_range><begin>1787788800</begin><end>1787875200</end></date_range>
          </report_metadata>
          <policy_published>
            <domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf>
            <p>{policy}</p><sp>{policy}</sp><pct>100</pct>
          </policy_published>
          {string.Join("\n  ", rows)}
        </feedback>
        """;

    private static string Row(
        string ip, int count, string dmarc, string headerFrom,
        string dkimDomain, string dkimResult, string spfDomain, string spfResult) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>{dmarc}</dkim><spf>{dmarc}</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{dkimDomain}</domain><result>{dkimResult}</result></dkim>
              <spf><domain>{spfDomain}</domain><result>{spfResult}</result></spf>
            </auth_results>
          </record>
        """;

    private async Task<ClientReport> BuildAsync(string xml)
    {
        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync(parsed.Report!.Policy.Domain, slug!);

        // The fixture's date range sits in this month, whichever month that is
        // when the suite runs, so the period is derived from it rather than
        // from the clock.
        var begin = parsed.Report.Metadata.Begin;
        var report = await new ClientReportBuilder(_dbPath)
            .BuildAsync(slug!, ReportPeriod.ForMonth(begin.Year, begin.Month), "NRG Tech Services");

        Assert.NotNull(report);
        return report!;
    }

    // ---- the distinction the product exists to make --------------------------

    [Fact]
    public async Task ASourceThatAuthenticatesMostlyAndFailsUnprovenIsNotCalledMisconfigured()
    {
        // Taken from real data: four rows pass, one fails having proved
        // nothing. Judging the source on all five rows labels it a service of
        // the client's own that needs correcting, and the message nobody could
        // account for turns into a maintenance note.
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("35.174.145.124", 11, "pass", "acme.com", "acme.com", "pass", "acme.com", "fail"),
            Row("35.174.145.124", 1, "fail", "acme.com", "acme.com", "fail", "acme.com", "fail")));

        var source = Assert.Single(report.ImpersonatingSources);
        Assert.Equal("35.174.145.124", source.SourceIp);
        Assert.Equal(1, source.Failing);
        Assert.Equal(12, source.Messages);
        Assert.Empty(report.MisconfiguredSources);
    }

    [Fact]
    public async Task ASourceSigningAsItselfAndFailingIsAMisconfiguredService()
    {
        // The genuine article: Mailchimp signing as mailchimpapp.net while the
        // header says acme.com. Real mail of the client's, being lost.
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("198.51.100.7", 55, "fail", "acme.com", "mailchimpapp.net", "pass", "mailchimpapp.net", "pass")));

        var source = Assert.Single(report.MisconfiguredSources);
        Assert.Equal("mailchimpapp.net", source.AuthenticatedFor);
        Assert.Empty(report.ImpersonatingSources);
    }

    [Fact]
    public async Task ASourceThatProvesNothingAtAllIsImpersonation()
    {
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("203.0.113.9", 20, "fail", "acme.com", "", "fail", "bounce.example", "fail")));

        var source = Assert.Single(report.ImpersonatingSources);
        Assert.Equal("203.0.113.9", source.SourceIp);
        Assert.Empty(report.MisconfiguredSources);
    }

    [Fact]
    public async Task ACleanSourceAppearsOnceAndOnlyAsLegitimate()
    {
        // The three tables in the report have to be disjoint. A source in two
        // of them with two different counts reads as a contradiction.
        var report = await BuildAsync(Xml("acme.com", "reject",
            Row("192.0.2.25", 400, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")));

        Assert.Single(report.LegitimateSources);
        Assert.Empty(report.MisconfiguredSources);
        Assert.Empty(report.ImpersonatingSources);
    }

    [Fact]
    public async Task TheThreeBucketsNeverShareASource()
    {
        var report = await BuildAsync(Xml("acme.com", "reject",
            Row("192.0.2.25", 400, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass"),
            Row("198.51.100.7", 55, "fail", "acme.com", "mailchimpapp.net", "pass", "mailchimpapp.net", "pass"),
            Row("203.0.113.9", 20, "fail", "acme.com", "", "fail", "bounce.example", "fail")));

        var all = report.LegitimateSources
            .Concat(report.MisconfiguredSources)
            .Concat(report.ImpersonatingSources)
            .Select(s => s.SourceIp)
            .ToList();

        Assert.Equal(all.Count, all.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(3, all.Count);
    }

    // ---- totals --------------------------------------------------------------

    [Fact]
    public async Task CountsEveryMessageOnceAcrossTheWholeReport()
    {
        var report = await BuildAsync(Xml("acme.com", "reject",
            Row("192.0.2.25", 400, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass"),
            Row("203.0.113.9", 20, "fail", "acme.com", "", "fail", "bounce.example", "fail")));

        Assert.Equal(420, report.Messages);
        Assert.Equal(400, report.Passing);
        Assert.Equal(20, report.Failing);
        Assert.Equal(20, report.MessagesActedOn);
    }

    [Fact]
    public async Task NothingWasActedOnWhileTheDomainIsStillOnlyMonitoring()
    {
        // The number that answers "what am I paying for" must be zero at
        // p=none, whatever failed: nothing was stopped.
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("203.0.113.9", 20, "fail", "acme.com", "", "fail", "bounce.example", "fail")));

        Assert.Equal(0, report.MessagesActedOn);
    }

    [Fact]
    public async Task ReturnsNothingForAClientThatDoesNotExist()
    {
        var report = await new ClientReportBuilder(_dbPath)
            .BuildAsync("no-such-client", ReportPeriod.ForMonth(2026, 8));

        Assert.Null(report);
    }
}
