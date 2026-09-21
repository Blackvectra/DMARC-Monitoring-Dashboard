using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// The parser against reports that real receivers actually sent.
///
/// The prototype's parser was only ever tested against XML written to match
/// what the parser expected, which proves the author was self-consistent and
/// nothing else. Every assertion here is pinned to a real file, and the
/// quirks below were discovered by running against them rather than imagined
/// in advance.
/// </summary>
public sealed class RealReportTests
{
    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    // ---- gosecure.net: a small receiver, and the one that found a bug ------

    [Fact]
    public void ParsesTheGoSecureReport()
    {
        var result = AggregateReportParser.Parse(Fixture("gosecure-aggregate.xml"));

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("gosecure.net", report.Metadata.OrgName);
        Assert.Equal("nrgtechservices.com", report.Policy.Domain);
        Assert.Equal(DmarcPolicy.Reject, report.Policy.P);
        Assert.Equal(AlignmentMode.Strict, report.Policy.Adkim);
        Assert.Equal(AlignmentMode.Strict, report.Policy.Aspf);
        Assert.Single(report.Records);
    }

    [Fact]
    public void StripsTheTrailingDotFromAFullyQualifiedDomain()
    {
        // gosecure.net sends "nrgtechservices.com." with the root dot. Left
        // on, it never matches "nrgtechservices.com" when alignment is
        // checked, so a domain authenticating for itself gets reported as
        // authenticating for somebody else. This is the bug real data found.
        var report = AggregateReportParser.Parse(Fixture("gosecure-aggregate.xml")).Report!;

        var domains = report.Records[0].SpfResults.Select(r => r.Domain).ToList();
        Assert.Contains("nrgtechservices.com", domains);
        Assert.DoesNotContain(domains, d => d.EndsWith('.'));
    }

    [Fact]
    public void DropsTheEmptyDkimElementsGoSecureSends()
    {
        // The report carries four <dkim><domain/><result/></dkim> elements.
        // An AuthResult with no domain cannot be aligned against anything and
        // would render as an unexplained blank row in a client report.
        var report = AggregateReportParser.Parse(Fixture("gosecure-aggregate.xml")).Report!;

        Assert.Empty(report.Records[0].DkimResults);
        Assert.Equal(3, report.Records[0].SpfResults.Count);
    }

    [Fact]
    public void KeepsEverySpfResultWhenSeveralAreReported()
    {
        // Three SPF results for one message: two passes for other domains and
        // one failure for the domain itself. Keeping only the first would
        // report the opposite of what happened.
        var report = AggregateReportParser.Parse(Fixture("gosecure-aggregate.xml")).Report!;
        var spf = report.Records[0].SpfResults;

        Assert.Contains(spf, r => r.Domain == "a1i334.smtp2go.com" && r.IsPass);
        Assert.Contains(spf, r => r.Domain == "em318306.nrgtechservices.com" && r.IsPass);
        Assert.Contains(spf, r => r.Domain == "nrgtechservices.com" && !r.IsPass);
    }

    // ---- google.com --------------------------------------------------------

    [Fact]
    public void ParsesTheGoogleReport()
    {
        var result = AggregateReportParser.Parse(Fixture("google-aggregate.xml"));

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("google.com", report.Metadata.OrgName);
        Assert.Equal("5477767420649182103", report.Metadata.ReportId);
        Assert.NotEmpty(report.Records);
    }

    [Fact]
    public void CapturesTheNonExistentSubdomainPolicyGoogleReports()
    {
        // RFC 9091 np=. Worth surfacing: a domain can sit at p=reject while
        // subdomains nobody ever registered stay open to impersonation.
        var report = AggregateReportParser.Parse(Fixture("google-aggregate.xml")).Report!;
        Assert.Equal(DmarcPolicy.Reject, report.Policy.Np);
    }

    [Fact]
    public void HandlesIpv6SourceAddresses()
    {
        var report = AggregateReportParser.Parse(Fixture("google-aggregate.xml")).Report!;
        Assert.Contains(report.Records, r => r.SourceIp.Contains(':', StringComparison.Ordinal));
    }

    [Fact]
    public void IgnoresElementsItDoesNotModel()
    {
        // <version> and <extra_contact_info> are present and unmodeled.
        // Unknown elements must be skipped, never treated as an error.
        Assert.True(AggregateReportParser.Parse(Fixture("google-aggregate.xml")).Success);
    }

    // ---- Enterprise Outlook: 123 records ------------------------------------

    [Fact]
    public void ParsesTheOutlookReport()
    {
        var result = AggregateReportParser.Parse(Fixture("outlook-aggregate.xml"));

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("Enterprise Outlook", report.Metadata.OrgName);
        Assert.Equal(123, report.Records.Count);
    }

    [Fact]
    public void ParsesAReportDeclaringXmlSchemaNamespaces()
    {
        // Outlook declares xmlns:xsd and xmlns:xsi on the root. Matching on
        // fully-qualified names rather than local names would find nothing.
        Assert.True(AggregateReportParser.Parse(Fixture("outlook-aggregate.xml")).Success);
    }

    [Fact]
    public void CapturesEnvelopeIdentifiersWhenPresent()
    {
        // Outlook reports envelope_from and envelope_to; most receivers do not.
        var report = AggregateReportParser.Parse(Fixture("outlook-aggregate.xml")).Report!;
        Assert.Contains(report.Records, r => !string.IsNullOrEmpty(r.EnvelopeFrom));
    }

    [Fact]
    public void CapturesTheForensicOptionsTag()
    {
        var report = AggregateReportParser.Parse(Fixture("outlook-aggregate.xml")).Report!;
        Assert.Equal("1", report.Policy.Fo);
    }

    [Fact]
    public void TotalsAreInternallyConsistentAcrossAllRecords()
    {
        // 123 records is enough for an arithmetic slip to hide in.
        var report = AggregateReportParser.Parse(Fixture("outlook-aggregate.xml")).Report!;

        Assert.Equal(report.TotalMessages, report.PassingMessages + report.FailingMessages);
        Assert.True(report.TotalMessages > 0);
        Assert.Equal(report.Records.Sum(r => (long)r.Count), report.TotalMessages);
    }

    [Fact]
    public void EveryRecordHasASourceItCanBeAttributedTo()
    {
        var report = AggregateReportParser.Parse(Fixture("outlook-aggregate.xml")).Report!;
        Assert.All(report.Records, r => Assert.False(string.IsNullOrWhiteSpace(r.SourceIp)));
    }

    // ---- across every real report -------------------------------------------

    [Theory]
    [InlineData("gosecure-aggregate.xml")]
    [InlineData("google-aggregate.xml")]
    [InlineData("outlook-aggregate.xml")]
    public void EveryRealReportParsesCleanly(string fixture)
    {
        var result = AggregateReportParser.Parse(Fixture(fixture));

        Assert.True(result.Success, $"{fixture}: {result.Error}");
        Assert.Equal("nrgtechservices.com", result.Report!.Policy.Domain);
    }

    [Theory]
    [InlineData("gosecure-aggregate.xml")]
    [InlineData("google-aggregate.xml")]
    [InlineData("outlook-aggregate.xml")]
    public void NoRealReportProducesADomainWithATrailingDotAnywhere(string fixture)
    {
        var report = AggregateReportParser.Parse(Fixture(fixture)).Report!;

        Assert.NotEmpty(report.Policy.Domain);
        Assert.False(report.Policy.Domain.EndsWith('.'));
        foreach (var rec in report.Records)
        {
            Assert.False(rec.HeaderFrom.EndsWith('.'));
            Assert.All(rec.SpfResults, a => Assert.False(a.Domain.EndsWith('.')));
            Assert.All(rec.DkimResults, a => Assert.False(a.Domain.EndsWith('.')));
        }
    }

    [Theory]
    [InlineData("gosecure-aggregate.xml")]
    [InlineData("google-aggregate.xml")]
    [InlineData("outlook-aggregate.xml")]
    public void NoAuthResultIsRetainedWithoutADomain(string fixture)
    {
        var report = AggregateReportParser.Parse(Fixture(fixture)).Report!;

        foreach (var rec in report.Records)
        {
            Assert.All(rec.SpfResults, a => Assert.False(string.IsNullOrWhiteSpace(a.Domain)));
            Assert.All(rec.DkimResults, a => Assert.False(string.IsNullOrWhiteSpace(a.Domain)));
        }
    }
}
