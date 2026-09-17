using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// A second real client, rivercityboats.com, reported on by five more
/// receivers: Yahoo, AOL, Rocketmail, AT&amp;T and Outlook.com.
///
/// Valuable for two reasons beyond more coverage.
///
/// The Yahoo family (yahoo.com, aol.com, rocketmail.com and att.net are all
/// operated by Yahoo) all report 100% passing, while Outlook.com reports 0%.
/// That is not a contradiction: they saw different mail. It is the clearest
/// possible demonstration of why a report is one receiver's view and why
/// averaging across receivers produces a number that describes nothing.
///
/// And the Outlook.com report contains a textbook authenticated-but-not-
/// aligned failure: Mailchimp sending as the client while signing as its own
/// domains, so 55 messages were quarantined.
/// </summary>
public sealed class SecondClientReportTests
{
    /// <summary>
    /// yahoo.com, aol.com, rocketmail.com and att.net are all operated by
    /// Yahoo and report identically, so they are treated as one family.
    /// </summary>
    private static readonly string[] YahooFamily =
    [
        "rcb-yahoo-aggregate.xml",
        "rcb-aol-aggregate.xml",
        "rcb-rocketmail-aggregate.xml",
        "rcb-attnet-aggregate.xml",
    ];

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    private static AggregateReport Parse(string fixture)
    {
        var result = AggregateReportParser.Parse(Fixture(fixture));
        Assert.True(result.Success, $"{fixture}: {result.Error}");
        return result.Report!;
    }

    [Theory]
    [InlineData("rcb-yahoo-aggregate.xml")]
    [InlineData("rcb-aol-aggregate.xml")]
    [InlineData("rcb-rocketmail-aggregate.xml")]
    [InlineData("rcb-attnet-aggregate.xml")]
    [InlineData("rcb-outlookcom-aggregate.xml")]
    public void EveryReceiverParsesCleanly(string fixture)
    {
        Assert.Equal("rivercityboats.com", Parse(fixture).Policy.Domain);
    }

    [Theory]
    [InlineData("rcb-yahoo-aggregate.xml")]
    [InlineData("rcb-aol-aggregate.xml")]
    [InlineData("rcb-rocketmail-aggregate.xml")]
    [InlineData("rcb-attnet-aggregate.xml")]
    [InlineData("rcb-outlookcom-aggregate.xml")]
    public void EveryReceiverAgreesOnThePublishedPolicy(string fixture)
    {
        // Five independent receivers read the same DNS record. If the parser
        // disagreed with itself across them, one of the readings is wrong.
        Assert.Equal(DmarcPolicy.Quarantine, Parse(fixture).Policy.P);
    }

    [Theory]
    [InlineData("rcb-yahoo-aggregate.xml")]
    [InlineData("rcb-aol-aggregate.xml")]
    [InlineData("rcb-rocketmail-aggregate.xml")]
    [InlineData("rcb-attnet-aggregate.xml")]
    public void TheYahooFamilyReportsEverythingPassing(string fixture)
    {
        var report = Parse(fixture);
        Assert.True(report.TotalMessages > 0);
        Assert.Equal(report.TotalMessages, report.PassingMessages);
        Assert.Equal(0, report.FailingMessages);
    }

    [Fact]
    public void OutlookReportsEverythingFailingForTheSameDomainAndPeriod()
    {
        // Same domain, overlapping days, opposite result. Both are true: they
        // saw different mail. Nothing in the tool may quietly reconcile them.
        var report = Parse("rcb-outlookcom-aggregate.xml");

        Assert.Equal(55, report.TotalMessages);
        Assert.Equal(0, report.PassingMessages);
        Assert.Equal(55, report.FailingMessages);
    }

    [Fact]
    public void TheOutlookFailureIsAuthenticatedButNotAligned()
    {
        // The case worth getting right: Mailchimp authenticated perfectly, for
        // its own domains. DMARC counts only authentication matching the
        // address recipients see, so it is recorded as a failure. Calling this
        // an attack would send an operator to block their client's own
        // marketing mail; calling it a pass would hide 55 quarantined messages.
        var report = Parse("rcb-outlookcom-aggregate.xml");

        // Four records, all from the same Mailchimp relay, which is why the
        // explainer groups them into one sending source.
        Assert.Equal(4, report.Records.Count);
        Assert.All(report.Records, r =>
        {
            Assert.Equal(DmarcResult.Fail, r.Dkim);
            Assert.Equal(DmarcResult.Fail, r.Spf);
        });

        var authenticated = report.Records
            .SelectMany(r => r.SpfResults.Concat(r.DkimResults))
            .Where(a => a.IsPass)
            .ToList();
        Assert.NotEmpty(authenticated);

        // Every domain that authenticated belongs to Mailchimp, not the client.
        Assert.All(authenticated, a =>
            Assert.False(
                a.Domain.EndsWith("rivercityboats.com", StringComparison.Ordinal),
                $"{a.Domain} should not be the client's own domain"));

        Assert.Contains(authenticated, a => a.Domain.Contains("mailchimp", StringComparison.Ordinal)
                                         || a.Domain.Contains("rsgsv.net", StringComparison.Ordinal));
    }

    [Fact]
    public void AveragingAcrossReceiversWouldDescribeNothing()
    {
        // 39 passing at Yahoo plus 55 failing at Outlook averages to about
        // 41%, a number that matches neither receiver and hides that a whole
        // sending service is being quarantined. This is why the triage view
        // ranks rather than averages.
        var yahooFamily = YahooFamily.Select(Parse).ToList();
        var outlook = Parse("rcb-outlookcom-aggregate.xml");

        var familyTotal = yahooFamily.Sum(r => r.TotalMessages);
        Assert.Equal(familyTotal, yahooFamily.Sum(r => r.PassingMessages));
        Assert.Equal(0, outlook.PassingMessages);

        var combinedRate = (yahooFamily.Sum(r => r.PassingMessages) + outlook.PassingMessages) * 100.0
                         / (familyTotal + outlook.TotalMessages);
        Assert.InRange(combinedRate, 1, 99);   // matches neither receiver
    }

    [Fact]
    public void AttributesTheYahooFamilyReportsToYahoo()
    {
        // att.net, aol.com and rocketmail.com reports are all generated by
        // Yahoo. Storing them under four different reporter names would look
        // like four independent confirmations when it is really one.
        foreach (var fixture in YahooFamily)
        {
            Assert.Equal("Yahoo", Parse(fixture).Metadata.OrgName);
        }
    }

    [Fact]
    public void GivesEveryReceiverADistinctReportId()
    {
        // The four Yahoo-family reports share a reporter name, so the report
        // id is the only thing separating them. If they collided, three of the
        // four would be discarded as duplicates.
        var ids = YahooFamily.Select(f => Parse(f).Metadata.ReportId).ToList();

        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
    }
}
