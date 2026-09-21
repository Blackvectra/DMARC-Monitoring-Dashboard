using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Mail per day, which is what every chart draws.
///
/// The case worth most of these tests is the difference between a day on
/// which nothing was sent and a day nobody reported on. They are stored the
/// same way - no rows - and mean opposite things.
/// </summary>
public sealed class TimeSeriesServiceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-series-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public TimeSeriesServiceTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    /// <summary>One report covering one day, with rows that pass and rows that do not.</summary>
    private async Task StoreAsync(string domain, int daysAgo, int passing, int failing, string disposition = "none")
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var records = "";

        if (passing > 0)
        {
            records += $"""
                <record>
                  <row><source_ip>192.0.2.25</source_ip><count>{passing}</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                  <identifiers><header_from>{domain}</header_from></identifiers>
                  <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim>
                    <spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
                </record>
                """;
        }

        if (failing > 0)
        {
            records += $"""
                <record>
                  <row><source_ip>203.0.113.9</source_ip><count>{failing}</count>
                    <policy_evaluated><disposition>{disposition}</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
                  <identifiers><header_from>{domain}</header_from></identifiers>
                  <auth_results><dkim><domain>{domain}</domain><result>fail</result></dkim>
                    <spf><domain>{domain}</domain><result>fail</result></spf></auth_results>
                </record>
                """;
        }

        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range></report_metadata>
              <policy_published><domain>{domain}</domain><p>reject</p><pct>100</pct></policy_published>
              {records}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    private TimeSeriesService Service() => new(_dbPath);

    // ---- the distinction the type exists for --------------------------------

    [Fact]
    public async Task ADayNobodyReportedOnIsMarkedUnreportedRatherThanZero()
    {
        // Drawn as zero this is a cliff to the floor and back, and somebody
        // spends an afternoon looking for an outage that never happened.
        await StoreAsync("acme.com", daysAgo: 4, passing: 100, failing: 0);
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 0);

        var series = await Service().DomainAsync("acme.com", days: 6);

        var quiet = series.Where(p => !p.Reported).ToList();
        Assert.NotEmpty(quiet);
        Assert.All(quiet, p => Assert.Equal(0, p.Messages));

        // And the chart is told to break rather than plot a number.
        Assert.All(quiet, p => Assert.Null(p.PassRate));
    }

    [Fact]
    public async Task ADayReportedWithNoMailIsARealZeroRatherThanAGap()
    {
        // A receiver can file a report covering a day the domain sent nothing
        // through it. That is a measured zero, and the line should cross it.
        await StoreAsync("acme.com", daysAgo: 1, passing: 0, failing: 0);

        var series = await Service().DomainAsync("acme.com", days: 3);
        var day = series.Single(p => p.Day == DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)));

        Assert.True(day.Reported);
        Assert.Equal(0, day.Messages);
    }

    [Fact]
    public async Task EveryDayInTheWindowGetsAPointEvenWithNoDataAtAll()
    {
        // A chart with fewer points than days silently compresses the axis,
        // so a week of silence looks like a week that did not happen.
        var series = await Service().DomainAsync("acme.com", days: 14);

        Assert.Equal(14, series.Count);
        Assert.All(series, p => Assert.False(p.Reported));
    }

    [Fact]
    public async Task ThePointsRunInDateOrderEndingToday()
    {
        var series = await Service().EstateAsync(days: 5);

        Assert.Equal(5, series.Count);
        Assert.Equal(DateOnly.FromDateTime(DateTime.UtcNow), series[^1].Day);
        Assert.Equal(series.OrderBy(p => p.Day).Select(p => p.Day), series.Select(p => p.Day));
    }

    // ---- the counts ---------------------------------------------------------

    [Fact]
    public async Task PassingAndFailingAreCountedSeparately()
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 90, failing: 10);

        var day = (await Service().DomainAsync("acme.com", days: 3))
            .Single(p => p.Messages > 0);

        Assert.Equal(100, day.Messages);
        Assert.Equal(90, day.Passing);
        Assert.Equal(10, day.Failing);
        Assert.Equal(90.0, day.PassRate);
    }

    [Fact]
    public async Task DispositionIsCountedOnlyOnMailThatActuallyFailed()
    {
        // A receiver stamps "none" on mail that passed too. Counting those
        // would make every domain look as though most of its mail had been let
        // through despite failing.
        await StoreAsync("acme.com", daysAgo: 1, passing: 900, failing: 100, disposition: "reject");

        var day = (await Service().DomainAsync("acme.com", days: 3)).Single(p => p.Messages > 0);

        Assert.Equal(100, day.Rejected);
        Assert.Equal(0, day.Quarantined);
        Assert.Equal(0, day.DeliveredAnyway);
    }

    [Fact]
    public async Task MailThatFailedAndWasDeliveredAnywayIsItsOwnCount()
    {
        // p=none, pct sampling, or a receiver override. It is the number that
        // says how much protection a policy is actually giving.
        await StoreAsync("acme.com", daysAgo: 1, passing: 10, failing: 40, disposition: "none");

        var day = (await Service().DomainAsync("acme.com", days: 3)).Single(p => p.Messages > 0);

        Assert.Equal(40, day.DeliveredAnyway);
        Assert.Equal(0, day.Rejected);
    }

    [Fact]
    public async Task DeliveredAnywayNeverGoesNegative()
    {
        // Receivers do report dispositions that do not add up. Whatever the
        // arithmetic, a chart must not be handed a negative segment.
        await StoreAsync("acme.com", daysAgo: 1, passing: 0, failing: 5, disposition: "reject");

        var day = (await Service().DomainAsync("acme.com", days: 3)).Single(p => p.Messages > 0);

        Assert.True(day.DeliveredAnyway >= 0);
    }

    [Fact]
    public async Task APassRateIsNotInventedForADayWithNoMessages()
    {
        // 0/0 is not 0%, and a chart plotting it at the floor says every
        // message failed.
        await StoreAsync("acme.com", daysAgo: 1, passing: 0, failing: 0);

        var day = (await Service().DomainAsync("acme.com", days: 3))
            .Single(p => p.Day == DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)));

        Assert.Null(day.PassRate);
    }

    // ---- scoping ------------------------------------------------------------

    [Fact]
    public async Task ADomainSeriesCountsOnlyThatDomain()
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 0);
        await StoreAsync("other.example", daysAgo: 1, passing: 500, failing: 0);

        var acme = await Service().DomainAsync("acme.com", days: 3);

        Assert.Equal(100, acme.Sum(p => p.Messages));
    }

    [Fact]
    public async Task TheEstateSeriesCountsEveryDomainTogether()
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 0);
        await StoreAsync("other.example", daysAgo: 1, passing: 500, failing: 0);

        var estate = await Service().EstateAsync(days: 3);

        Assert.Equal(600, estate.Sum(p => p.Messages));
    }

    [Fact]
    public async Task AClientSeriesCountsThatClientsDomainsOnly()
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 0);
        await StoreAsync("other.example", daysAgo: 1, passing: 500, failing: 0);

        var slug = await _store.CreateClientAsync("Acme Corp");
        await _store.AssignDomainAsync("acme.com", slug!);

        var client = await Service().ClientAsync(slug!, days: 3);

        Assert.Equal(100, client.Sum(p => p.Messages));
    }

    [Theory]
    [InlineData("ACME.com")]
    [InlineData("acme.com.")]
    [InlineData("  acme.com  ")]
    public async Task ADomainIsMatchedWithoutCareForCaseOrATrailingDot(string asked)
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 0);

        var series = await Service().DomainAsync(asked, days: 3);

        Assert.Equal(100, series.Sum(p => p.Messages));
    }

    [Fact]
    public async Task MailOutsideTheWindowIsNotCounted()
    {
        await StoreAsync("acme.com", daysAgo: 40, passing: 999, failing: 0);
        await StoreAsync("acme.com", daysAgo: 1, passing: 5, failing: 0);

        var series = await Service().DomainAsync("acme.com", days: 7);

        Assert.Equal(5, series.Sum(p => p.Messages));
    }

    // ---- the three-way split --------------------------------------------------

    /// <summary>A failing row the receiver declined to act on, as a forwarder produces.</summary>
    private async Task StoreForwardedAsync(string domain, int daysAgo, int count)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range></report_metadata>
              <policy_published><domain>{domain}</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>203.0.113.99</source_ip><count>{count}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                    <reason><type>forwarded</type><comment>mailing list</comment></reason>
                  </policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>fail</result></dkim>
                  <spf><domain>{domain}</domain><result>fail</result></spf></auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    [Fact]
    public async Task MailSplitsIntoAuthenticatedForwardedAndUnauthenticated()
    {
        // The split a pass rate cannot give. "95% passing" hides whether the
        // rest is forwarding, which is expected and not worth an afternoon, or
        // mail that proved nothing, which is the only part worth chasing.
        await StoreAsync("acme.com", daysAgo: 1, passing: 900, failing: 60);
        await StoreForwardedAsync("acme.com", daysAgo: 1, count: 40);

        var split = await Service().BreakdownAsync("acme.com", days: 7);

        Assert.Equal(900, split.Authenticated);
        Assert.Equal(40, split.Overridden);
        Assert.Equal(60, split.Unauthenticated);
        Assert.Equal(1000, split.Total);
    }

    [Fact]
    public async Task AnOverrideOnMailThatPASSEDDoesNotMoveItOutOfAuthenticated()
    {
        // Microsoft stamps "SPF ignored due to local policy" on traffic that
        // authenticated perfectly well by DKIM. Counting that as overridden
        // takes a domain's own clean mail out of the segment it belongs in.
        await StoreAsync("acme.com", daysAgo: 1, passing: 500, failing: 0);
        await StoreForwardedAsync("acme.com", daysAgo: 1, count: 5);

        var split = await Service().BreakdownAsync("acme.com", days: 7);

        Assert.Equal(500, split.Authenticated);
        Assert.Equal(5, split.Overridden);
    }

    [Fact]
    public async Task TheEstateSplitCoversEveryDomain()
    {
        await StoreAsync("acme.com", daysAgo: 1, passing: 100, failing: 10);
        await StoreAsync("other.example", daysAgo: 1, passing: 200, failing: 20);

        var split = await Service().BreakdownAsync(days: 7);

        Assert.Equal(300, split.Authenticated);
        Assert.Equal(30, split.Unauthenticated);
    }

    [Fact]
    public async Task NoMailGivesNoPassRateRatherThanZeroPerCent()
    {
        // 0/0 is not 0%, and a dial reading zero says every message failed.
        var split = await Service().BreakdownAsync("acme.com", days: 7);

        Assert.Equal(0, split.Total);
        Assert.Null(split.PassRate);
    }

    // ---- source compliance ----------------------------------------------------

    /// <summary>A service sending under its own envelope, signing its own domain.</summary>
    private async Task StoreServiceAsync(
        string domain, string envelope, string signing, int count, string evaluated,
        string spfResult = "pass", string dkimResult = "pass", int daysAgo = 1)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range></report_metadata>
              <policy_published><domain>{domain}</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>198.51.100.7</source_ip><count>{count}</count>
                  <policy_evaluated><disposition>none</disposition>
                    <dkim>{evaluated}</dkim><spf>{evaluated}</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results>
                  <dkim><domain>{signing}</domain><selector>s1</selector><result>{dkimResult}</result></dkim>
                  <spf><domain>{envelope}</domain><scope>mfrom</scope><result>{spfResult}</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    [Fact]
    public async Task ASourceIsNamedByTheEnvelopeItSendsUnder()
    {
        await StoreServiceAsync("acme.com", "em1234.acme.com", "acme.com", 500, "pass");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.Equal("em1234.acme.com", source.Source);
        Assert.Equal(500, source.Messages);
    }

    [Fact]
    public async Task ASourceWithNoEnvelopeFallsBackToWhatItSigned()
    {
        await StoreServiceAsync("acme.com", "", "vendor.example", 40, "fail", spfResult: "none");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.Equal("vendor.example", source.Source);
    }

    [Fact]
    public async Task MailThatNamesNeitherIsShownRatherThanDropped()
    {
        // A panel that quietly omits mail nobody can name overstates how well
        // the estate is doing.
        await StoreServiceAsync("acme.com", "", "", 25, "fail", spfResult: "none", dkimResult: "none");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.Equal("(not stated)", source.Source);
        Assert.Equal(25, source.Messages);
    }

    [Fact]
    public async Task TheThreeRatesAreCountedSeparately()
    {
        // SPF and DKIM are the raw checks; DMARC is those plus alignment. They
        // are three different questions and a source can answer them
        // differently.
        await StoreServiceAsync("acme.com", "psm.vendor.example", "vendor.example", 100, "fail");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.Equal(0, source.DmarcRate);
        Assert.Equal(100, source.SpfRate);
        Assert.Equal(100, source.DkimRate);
    }

    [Fact]
    public async Task ASourceThatAuthenticatesPerfectlyAndAlignsNeverIsFlagged()
    {
        // The single most misread situation in DMARC: SPF 100%, DKIM 100%,
        // DMARC 0%. Those numbers do not disagree - the service is
        // authenticating faultlessly for its own domain and counting for
        // nothing.
        await StoreServiceAsync("acme.com", "psm.vendor.example", "vendor.example", 100, "fail");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.True(source.AuthenticatesButDoesNotAlign);
    }

    [Fact]
    public async Task AHealthySourceIsNotFlagged()
    {
        await StoreServiceAsync("acme.com", "acme.com", "acme.com", 100, "pass");

        var source = Assert.Single(await Service().SourcesAsync("acme.com", days: 7));

        Assert.False(source.AuthenticatesButDoesNotAlign);
    }

    [Fact]
    public async Task SourcesComeBackBusiestFirstAndCapped()
    {
        for (var i = 0; i < 5; i++)
        {
            await StoreServiceAsync("acme.com", $"s{i}.example", "acme.com", (i + 1) * 10, "pass");
        }

        var sources = await Service().SourcesAsync("acme.com", days: 7, top: 3);

        Assert.Equal(3, sources.Count);
        Assert.Equal(50, sources[0].Messages);
        Assert.Equal(sources.OrderByDescending(s => s.Messages).Select(s => s.Messages), sources.Select(s => s.Messages));
    }

    [Fact]
    public async Task AskingForNoSourcesIsRefused()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => Service().SourcesAsync("acme.com", days: 7, top: 0));
    }

    // ---- active and inactive domains ------------------------------------------

    [Fact]
    public async Task DomainsThatSentNothingAreCountedAsInactive()
    {
        // A domain nobody sends as is not a domain that is safe: it is one
        // whose DMARC record nobody is watching.
        await StoreAsync("busy.example", daysAgo: 1, passing: 100, failing: 0);
        await StoreAsync("quiet.example", daysAgo: 60, passing: 100, failing: 0);

        var (active, inactive) = await Service().DomainActivityAsync(days: 7);

        Assert.Equal(1, active);
        Assert.Equal(1, inactive);
    }

    [Fact]
    public async Task ActivityCountsNeverGoNegative()
    {
        var (active, inactive) = await Service().DomainActivityAsync(days: 7);

        Assert.True(active >= 0);
        Assert.True(inactive >= 0);
    }

    [Fact]
    public async Task AWindowOfNothingIsRefusedRatherThanRenderedBlank()
    {
        // Silently returning no points draws an empty panel with nothing to
        // explain it, which reads as "no data" rather than "bad call".
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => Service().DomainAsync("acme.com", days: 0));
    }
}
