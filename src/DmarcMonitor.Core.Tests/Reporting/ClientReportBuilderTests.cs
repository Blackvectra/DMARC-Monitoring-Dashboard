using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Assembling a client report from stored data.
///
/// The judgment being tested is the one the whole product turns on: telling a
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
        _store.InitializeAsync(File.ReadAllText(FindSchema())).GetAwaiter().GetResult();
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

    /// <summary>Stores a report dated into a given month of 2026.</summary>
    private async Task StoreAsync(string xml, int month)
    {
        var begin = new DateTimeOffset(2026, month, 15, 0, 0, 0, TimeSpan.Zero);
        xml = System.Text.RegularExpressions.Regex.Replace(
            xml,
            @"<date_range><begin>\d+</begin><end>\d+</end></date_range>",
            $"<date_range><begin>{begin.ToUnixTimeSeconds()}</begin>"
            + $"<end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>");

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

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
    public async Task ASourceThatHasEverPassedIsTheClientsOwnMailPath()
    {
        // This test previously asserted the opposite, on the reasoning that
        // the failing row proved nothing so the source must be impersonating.
        // The live data settled it: 35.174.145.124 is a mail gateway carrying
        // these customers' outbound, and it both signs successfully and breaks
        // its own signatures in transit for every one of them. Passing even
        // once is the thing a forger cannot do, so it decides the bucket.
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("35.174.145.124", 11, "pass", "acme.com", "acme.com", "pass", "acme.com", "fail"),
            Row("35.174.145.124", 1, "fail", "acme.com", "acme.com", "fail", "acme.com", "fail")));

        var source = Assert.Single(report.MisconfiguredSources);
        Assert.Equal("35.174.145.124", source.SourceIp);
        Assert.Equal(1, source.Failing);
        Assert.Equal(12, source.Messages);
        Assert.Empty(report.ImpersonatingSources);
    }

    [Fact]
    public async Task ARelayIsNotAccusedEvenWhenItBreaksFarMoreOftenThanItWorks()
    {
        // dmvwrr.com in the live data: 113 signatures passed, 239 broke, one
        // address. The report put all 239 under "who tried to send mail as
        // you" and told the client somebody was sending as them 177 times.
        var report = await BuildAsync(Xml("acme.com", "none",
            Row("35.174.145.124", 113, "pass", "acme.com", "acme.com", "pass", "acme.com", "fail"),
            Row("35.174.145.124", 239, "fail", "acme.com", "acme.com", "fail", "acme.com", "fail")));

        Assert.Empty(report.ImpersonatingSources);
        Assert.Single(report.MisconfiguredSources);
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

    // ---- a report describes its period, and nothing after it ------------------

    [Fact]
    public async Task ReportsThePolicyAsItWasThenRatherThanAsItIsNow()
    {
        // A domain that advanced from none to reject in September must not
        // have its May report claim it was protected in May. Regenerating an
        // old month is exactly when this bites, and the wrongness is invisible
        // - the number looks plausible and flatters the provider.
        await StoreAsync(Xml("acme.com", "none",
            Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 5);
        await StoreAsync(Xml("acme.com", "reject",
            Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 9);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        var may = await new ClientReportBuilder(_dbPath).BuildAsync(slug!, ReportPeriod.ForMonth(2026, 5));
        var september = await new ClientReportBuilder(_dbPath).BuildAsync(slug!, ReportPeriod.ForMonth(2026, 9));

        Assert.Equal("none", Assert.Single(may!.Domains).Policy);
        Assert.Equal("reject", Assert.Single(september!.Domains).Policy);
    }

    [Fact]
    public async Task SaysThePolicyIsNotKnownRatherThanAssumingItWasUnprotected()
    {
        // Nothing had reached us by May. "p=none" would assert the domain was
        // published without protection; the truth is that nobody told us.
        await StoreAsync(Xml("acme.com", "quarantine",
            Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 9);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        var may = await new ClientReportBuilder(_dbPath).BuildAsync(slug!, ReportPeriod.ForMonth(2026, 5));

        var domain = Assert.Single(may!.Domains);
        Assert.False(domain.PolicyKnown);
    }

    [Fact]
    public async Task APeriodWithReportsKnowsItsPolicy()
    {
        await StoreAsync(Xml("acme.com", "quarantine",
            Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 9);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        var september = await new ClientReportBuilder(_dbPath).BuildAsync(slug!, ReportPeriod.ForMonth(2026, 9));

        Assert.True(Assert.Single(september!.Domains).PolicyKnown);
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

    /// <summary>
    /// Which month a month picker should open on.
    /// </summary>
    /// <remarks>
    /// It used to open on the last month that had ENDED, which on a
    /// three-week-old install is a month from before it existed. A real
    /// report went to a customer that way: two pages whose entire content was
    /// "No DMARC reports arrived for August 2026", generated from a database
    /// holding three weeks of September.
    /// </remarks>
    [Fact]
    public async Task FindsTheMostRecentMonthAClientHasDataFor()
    {
        await StoreAsync(Xml("acme.com", "none", Row("203.0.113.1", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 7);
        await StoreAsync(Xml("acme.com", "none", Row("203.0.113.1", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 9);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        Assert.Equal("2026-09", await new ClientReportBuilder(_dbPath).LatestMonthWithDataAsync(slug!));
    }

    [Fact]
    public async Task AClientWithNoDataHasNoMonth()
    {
        var slug = await _store.CreateClientAsync("Acme Corp");

        Assert.Null(await new ClientReportBuilder(_dbPath).LatestMonthWithDataAsync(slug!));
    }

    [Fact]
    public async Task AClientNobodyHasHeardOfHasNoMonth()
    {
        Assert.Null(await new ClientReportBuilder(_dbPath).LatestMonthWithDataAsync("no-such-client"));
    }

    /// <summary>
    /// Scoped like every other read here. A month learned from another
    /// organization's rows would be a small leak and a silly one to make in
    /// a convenience.
    /// </summary>
    [Fact]
    public async Task DoesNotSeeAMonthBelongingToAnotherOrganization()
    {
        await StoreAsync(Xml("acme.com", "none", Row("203.0.113.1", 10, "pass", "acme.com", "acme.com", "pass", "acme.com", "pass")), month: 9);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        Assert.Null(await new ClientReportBuilder(_dbPath)
            .LatestMonthWithDataAsync(slug!, tenantId: "some-other-organization"));
    }
}
