using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// Every real report, from every receiver, across every client domain.
///
/// Individual fixtures pin down specific quirks. This class asserts the
/// properties that must hold for ALL of them, so a change made to satisfy one
/// receiver cannot quietly break another. The corpus is the regression suite
/// that matters: it is what real receivers actually sent, not what the RFC
/// says they should.
///
/// Receivers so far: google.com, Enterprise Outlook, Outlook.com, Yahoo
/// (covering yahoo.com, aol.com, rocketmail.com and att.net), gosecure.net
/// and Mimecast. Client domains: nrgtechservices.com, rivercityboats.com,
/// lcdgroup.org and wahpeton.com.
/// </summary>
public sealed class CorpusTests
{
    /// <summary>Fixture name paired with the domain the report is about.</summary>
    public static TheoryData<string, string> EveryAggregateReport => new()
    {
        { "google-aggregate.xml", "nrgtechservices.com" },
        { "outlook-aggregate.xml", "nrgtechservices.com" },
        { "gosecure-aggregate.xml", "nrgtechservices.com" },
        { "rcb-yahoo-aggregate.xml", "rivercityboats.com" },
        { "rcb-aol-aggregate.xml", "rivercityboats.com" },
        { "rcb-rocketmail-aggregate.xml", "rivercityboats.com" },
        { "rcb-attnet-aggregate.xml", "rivercityboats.com" },
        { "rcb-outlookcom-aggregate.xml", "rivercityboats.com" },
        { "lcd-mimecast-aggregate.xml", "lcdgroup.org" },
        { "lcd-outlookcom-aggregate.xml", "lcdgroup.org" },
        { "lcd-yahoo-aggregate.xml", "lcdgroup.org" },
        { "wahpeton-google-aggregate.xml", "wahpeton.com" },
    };

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    private static AggregateReport Parse(string fixture)
    {
        var result = AggregateReportParser.Parse(Fixture(fixture));
        Assert.True(result.Success, $"{fixture}: {result.Error}");
        return result.Report!;
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void ParsesAndAttributesToTheRightDomain(string fixture, string domain)
    {
        Assert.Equal(domain, Parse(fixture).Policy.Domain);
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void NamesTheReceiverThatSentIt(string fixture, string domain)
    {
        _ = domain;
        // Without this the report cannot be attributed to a reporter, and the
        // duplicate key (reporter + report id + domain) collapses.
        Assert.NotEmpty(Parse(fixture).Metadata.OrgName);
        Assert.NotEmpty(Parse(fixture).Metadata.ReportId);
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void CountsAddUp(string fixture, string domain)
    {
        _ = domain;
        var report = Parse(fixture);

        Assert.Equal(report.TotalMessages, report.PassingMessages + report.FailingMessages);
        Assert.Equal(report.Records.Sum(r => (long)r.Count), report.TotalMessages);
        Assert.True(report.TotalMessages > 0, "a real report describes at least one message");
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void EveryRecordCanBeActedOn(string fixture, string domain)
    {
        _ = domain;
        foreach (var record in Parse(fixture).Records)
        {
            // A record with no source cannot be attributed, explained or
            // fixed, so it must never survive parsing.
            Assert.False(string.IsNullOrWhiteSpace(record.SourceIp));
            Assert.True(record.Count >= 0);
        }
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void NoDomainAnywhereKeepsItsTrailingDot(string fixture, string domain)
    {
        _ = domain;
        // The bug gosecure.net found. Checked across the whole corpus so a
        // future change cannot reintroduce it for one receiver only.
        var report = Parse(fixture);
        Assert.False(report.Policy.Domain.EndsWith('.'));

        foreach (var record in report.Records)
        {
            Assert.False(record.HeaderFrom.EndsWith('.'));
            Assert.All(record.SpfResults, a => Assert.False(a.Domain.EndsWith('.')));
            Assert.All(record.DkimResults, a => Assert.False(a.Domain.EndsWith('.')));
        }
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void NoAuthResultSurvivesWithoutADomain(string fixture, string domain)
    {
        _ = domain;
        // gosecure.net sends empty <dkim><domain/><result/></dkim> elements.
        // One kept would render as an unexplained blank row in a client report.
        foreach (var record in Parse(fixture).Records)
        {
            Assert.All(record.SpfResults, a => Assert.False(string.IsNullOrWhiteSpace(a.Domain)));
            Assert.All(record.DkimResults, a => Assert.False(string.IsNullOrWhiteSpace(a.Domain)));
        }
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void ReadsTheReportingWindow(string fixture, string domain)
    {
        _ = domain;
        var report = Parse(fixture);

        Assert.True(report.Metadata.Begin > DateTimeOffset.MinValue, "the window start must parse");
        Assert.True(report.Metadata.End >= report.Metadata.Begin, "the window must not run backwards");
    }

    [Theory]
    [MemberData(nameof(EveryAggregateReport))]
    public void IsRecognisedAsADmarcReportByContentAlone(string fixture, string domain)
    {
        _ = domain;
        // Ingest classifies by content, never by file name, because receivers
        // disagree about naming. Every real report must pass that check.
        Assert.Equal(ReportKind.DmarcAggregate, ReportAttachment.Classify(Fixture(fixture)));
    }

    [Fact]
    public void CoversEnoughReceiversToBeWorthCallingACorpus()
    {
        // A guard against the corpus quietly shrinking: if fixtures are moved
        // or renamed, this fails rather than the suite silently testing less.
        var reporters = EveryAggregateReport
            .Select(row => Parse((string)row[0]).Metadata.OrgName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(reporters.Count >= 5, $"expected several distinct receivers, got: {string.Join(", ", reporters)}");
    }

    [Fact]
    public void CoversSeveralClientDomains()
    {
        var domains = EveryAggregateReport
            .Select(row => Parse((string)row[0]).Policy.Domain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(domains.Count >= 4, $"expected several client domains, got: {string.Join(", ", domains)}");
    }

    [Fact]
    public void ReadsASubdomainPolicyStricterThanTheParent()
    {
        // lcdgroup.org publishes p=quarantine with sp=reject. Treating sp as
        // merely inheriting p would understate how protected subdomains are,
        // and the distinction is exactly what the sp tag exists for.
        var report = Parse("lcd-mimecast-aggregate.xml");

        Assert.Equal(DmarcPolicy.Quarantine, report.Policy.P);
        Assert.Equal(DmarcPolicy.Reject, report.Policy.Sp);
    }
}
