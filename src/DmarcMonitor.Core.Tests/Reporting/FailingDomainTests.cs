using DmarcMonitor.Core.Reporting;
using Xunit;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// One domain failing inside an estate that averages well.
///
/// This is the fault worth having a file of its own for, because nobody has
/// to intend it. A competitor's PDF, checked against its own CSV, announced
/// "100% DMARC Compliance" and "0 Total Issues" for a domain where 55 of 496
/// messages aligned with neither SPF nor DKIM and 51 were quarantined - a
/// true rate of 88.9%. An average did that, not a lie.
///
/// The same arithmetic was in this report. A real client's September had
/// three domains at 100%, 100% and 45.5%; the estate came to 96.6%, every
/// estate-wide check passed, and the document opened with "Your domains are
/// protected, and attempts to send mail as you were stopped" while more than
/// half of one domain's mail was not arriving.
/// </summary>
public sealed class FailingDomainTests
{
    private static ReportDomainHealth Domain(string name, long messages, long passing) => new()
    {
        Domain = name,
        Policy = "quarantine",
        Messages = messages,
        Passing = passing,
    };

    /// <summary>The real shape: 44 + 11 + 121 messages, one domain at 45.5%.</summary>
    private static ClientReport Report(IReadOnlyList<ReportDomainHealth> domains) => new()
    {
        ClientName = "Dunn County",
        ProviderName = "NRG TechServices",
        Period = ReportPeriod.ForMonth(2026, 9),
        Domains = domains,
        Messages = domains.Sum(d => d.Messages),
        Passing = domains.Sum(d => d.Passing),
        Failing = domains.Sum(d => d.Failing),
    };

    private static ClientReport RealShape() => Report(
    [
        Domain("dunncountynd.gov", 44, 44),
        Domain("mcleanelectric.com", 11, 5),
        Domain("ndaco.org", 121, 121),
    ]);

    [Fact]
    public void TheEstateAverageReallyDoesLookHealthy()
    {
        // The premise. Without this the rest of the file is testing a
        // threshold nobody would have crossed.
        var report = RealShape();

        Assert.Equal(96.6, report.PassRate);
        Assert.True(report.PassRate > ClientReport.HealthyPassRate);
    }

    [Fact]
    public void TheFailingDomainIsFoundAnyway()
    {
        var struggling = Assert.Single(RealShape().StrugglingDomains);

        Assert.Equal("mcleanelectric.com", struggling.Domain);
        Assert.Equal(45.5, struggling.PassRate);
        Assert.Equal(6, struggling.Failing);
    }

    [Fact]
    public void TheHeadlineNamesItRatherThanCallingTheMonthQuiet()
    {
        var summary = ReportNarrative.Summarize(RealShape());

        Assert.Contains("mcleanelectric.com", summary.Headline, StringComparison.Ordinal);
        Assert.Contains("failing", summary.Headline, StringComparison.Ordinal);
        Assert.DoesNotContain("nothing needed attention", summary.Headline, StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);
    }

    /// <summary>
    /// The count, not only the percentage.
    /// </summary>
    /// <remarks>
    /// "45.5%" is a number to scroll past. "6 message(s) may not have
    /// arrived" is a thing that happened to somebody, and it is what a client
    /// reads back to their own staff.
    /// </remarks>
    [Fact]
    public void TheSupportingPointGivesTheMessagesAndNotJustTheRate()
    {
        var summary = ReportNarrative.Summarize(RealShape());
        var text = string.Join(" ", summary.Points);

        Assert.Contains("mcleanelectric.com", text, StringComparison.Ordinal);
        Assert.Contains("45.5%", text, StringComparison.Ordinal);
        Assert.Contains("6 message(s) may not have arrived", text, StringComparison.Ordinal);
    }

    [Fact]
    public void SeveralFailingDomainsAreCountedRatherThanListedInTheHeadline()
    {
        var summary = ReportNarrative.Summarize(Report(
        [
            Domain("a.example", 100, 100),
            Domain("b.example", 100, 40),
            Domain("c.example", 100, 10),
        ]));

        Assert.Contains("2 of them are losing mail", summary.Headline, StringComparison.Ordinal);

        // Worst first, and both named where there is room to name them.
        var text = string.Join(" ", summary.Points);
        Assert.Contains("c.example at 10%", text, StringComparison.Ordinal);
        Assert.Contains("b.example at 40%", text, StringComparison.Ordinal);
        Assert.True(
            text.IndexOf("c.example", StringComparison.Ordinal) < text.IndexOf("b.example", StringComparison.Ordinal),
            "the worst domain should be named first");
    }

    [Fact]
    public void AnEstateWhereEveryDomainIsFineIsStillAllowedToSaySo()
    {
        // The check must not fire on every report, or it says nothing.
        var summary = ReportNarrative.Summarize(Report(
        [
            Domain("a.example", 100, 100),
            Domain("b.example", 100, 99),
        ]));

        Assert.Empty(Report([Domain("a.example", 100, 100)]).StrugglingDomains);
        Assert.Contains("nothing needed attention", summary.Headline, StringComparison.Ordinal);
        Assert.False(summary.NeedsAttention);
    }

    /// <summary>
    /// A domain that sent nothing is not a domain that failed.
    /// </summary>
    /// <remarks>
    /// Zero of zero is 0%, which is below any threshold and means nothing at
    /// all. Reporting it as a failing domain would put a client's dormant
    /// domain in the headline every month.
    /// </remarks>
    [Fact]
    public void ADomainThatSentNothingIsNotFailing()
    {
        var report = Report([Domain("live.example", 100, 100), Domain("dormant.example", 0, 0)]);

        Assert.Empty(report.StrugglingDomains);
        Assert.False(ReportNarrative.Summarize(report).NeedsAttention);
    }

    /// <summary>
    /// Not yet protected still outranks a failing domain in the headline.
    /// </summary>
    /// <remarks>
    /// A clean month at p=none means anybody can send as this client and it
    /// will be delivered, which is worse than some of their own mail failing
    /// while a policy is in force.
    /// </remarks>
    [Fact]
    public void BeingUnprotectedIsStillTheFirstThingSaid()
    {
        var summary = ReportNarrative.Summarize(Report(
        [
            new ReportDomainHealth { Domain = "a.example", Policy = "none", Messages = 100, Passing = 10 },
        ]));

        Assert.Contains("not yet protected", summary.Headline, StringComparison.Ordinal);
    }
}

/// <summary>
/// Naming the sources in the document a client reads.
///
/// The Sources page has named these since reverse lookups were stored and the
/// report did not, so a customer was handed a row of digits and asked whether
/// they recognized it. Nobody recognizes an address.
/// </summary>
public sealed class NamedSourceTests
{
    private static ReportSource Source(string ip, string name = "", long messages = 6, long passing = 0) => new()
    {
        SourceIp = ip,
        ReverseName = name,
        Messages = messages,
        Passing = passing,
        Failing = messages - passing,
        Domains = ["mcleanelectric.com"],
    };

    private static ClientReport Report(params ReportSource[] sources) => new()
    {
        ClientName = "Dunn County",
        ProviderName = "NRG TechServices",
        Period = ReportPeriod.ForMonth(2026, 9),
        Domains = [new ReportDomainHealth { Domain = "mcleanelectric.com", Policy = "quarantine", Messages = 11, Passing = 5 }],
        Sources = sources,
        Messages = 11,
        Passing = 5,
        Failing = 6,
    };

    [Fact]
    public void ANamedSourceReadsAsItsNameAndKeepsItsAddress()
    {
        // The real one, from their own September: a Contabo VPS sending as a
        // customer's domain. "vmi3366424.contaboserver.net" is a finding;
        // "13.140.173.0" is homework.
        var html = ClientReportRenderer.ToHtml(
            Report(Source("13.140.173.0", "vmi3366424.contaboserver.net")));

        Assert.Contains("vmi3366424.contaboserver.net", html, StringComparison.Ordinal);

        // Both, never one. The name is what a person reads; the address is
        // what they have to quote to a hosting provider, and it is the part
        // that is verifiable - a PTR is written by whoever holds the address.
        Assert.Contains("13.140.173.0", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAddressWithNoNameIsStillShownPlainly()
    {
        var html = ClientReportRenderer.ToHtml(Report(Source("198.51.100.4")));

        Assert.Contains("198.51.100.4", html, StringComparison.Ordinal);

        // The markup, not the class name: the stylesheet defines .src-name on
        // every report whether or not any row uses it.
        Assert.DoesNotContain("<span class=\"src-name\">", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A reverse name is for reading, never for judging.
    /// </summary>
    /// <remarks>
    /// A PTR is written by whoever holds the address, so a forger can put any
    /// name they like on their own. If a name could move a source out of "who
    /// tried to send mail as you", the cheapest possible lie would defeat the
    /// whole section.
    /// </remarks>
    [Fact]
    public void ANameDoesNotChangeWhetherASourceIsImpersonating()
    {
        var anonymous = Report(Source("198.51.100.4"));
        var flattering = Report(Source("198.51.100.4", "mail.mcleanelectric.com"));

        Assert.Single(anonymous.ImpersonatingSources);
        Assert.Single(flattering.ImpersonatingSources);
    }
}
