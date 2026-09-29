using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using Xunit;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// The health check reading the engines' own records and the open critical
/// findings: an engine that failed is broken now, one that has never run is
/// not health, and open criticals are a check rather than an alert.
/// </summary>
public sealed class HealthEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 3, 30, 0, TimeSpan.Zero);

    [Fact]
    public void AnEngineThatFailedItsLastRunIsBroken()
    {
        var facts = new HealthFacts
        {
            Sources = [new SourceFacts("local", null, FindingSourceIds.Reports, SourceHealth.Failed, Now.AddHours(-2), "the certificate has expired")],
        };

        var finding = Assert.Single(HealthCheck.Assess(facts, Now), f => f.Record == "engine");

        Assert.Equal(HygieneSeverity.Breaking, finding.Severity);
        Assert.Contains("reports engine for local", finding.Problem, StringComparison.Ordinal);
        Assert.Contains("the certificate has expired", finding.Problem, StringComparison.Ordinal);
        Assert.Contains("marked unknown rather than resolved", finding.Problem, StringComparison.Ordinal);
        Assert.Contains("dmarc-ingest", finding.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEngineThatHasNotRunIsAWeaknessAndOneThatNeverHasIsNotHealth()
    {
        var facts = new HealthFacts
        {
            Sources =
            [
                new SourceFacts("local", "acme-corp", FindingSourceIds.DnsScan, SourceHealth.Stale, Now.AddDays(-3), null),
                new SourceFacts("local", null, FindingSourceIds.Reports, SourceHealth.Unknown, null, null),
                new SourceFacts("other", null, FindingSourceIds.Reports, SourceHealth.Healthy, Now.AddMinutes(-20), null),
            ],
        };

        var findings = HealthCheck.Assess(facts, Now).Where(f => f.Record == "engine").ToList();

        Assert.Equal(2, findings.Count);
        var stale = Assert.Single(findings, f => f.Severity == HygieneSeverity.Weakness);
        Assert.Contains("dns-scan engine for local (acme-corp)", stale.Problem, StringComparison.Ordinal);
        Assert.Contains("dmarc check --all --save", stale.Fix, StringComparison.Ordinal);
        var never = Assert.Single(findings, f => f.Severity == HygieneSeverity.Tidy);
        Assert.Contains("never recorded a successful run", never.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenCriticalFindingsAreACheckNamingTheDomainsNotAnAlert()
    {
        var facts = new HealthFacts
        {
            Critical = [new CriticalFacts("local", 7, ["a.example", "b.example", "c.example", "d.example", "e.example"]), new CriticalFacts("other", 0, [])],
        };

        var finding = Assert.Single(HealthCheck.Assess(facts, Now), f => f.Record == "findings");

        Assert.Equal(HygieneSeverity.Weakness, finding.Severity);
        Assert.StartsWith("7 critical findings open for local", finding.Problem, StringComparison.Ordinal);
        Assert.Contains("a.example, b.example, c.example, d.example, e.example, and 2 more", finding.Problem, StringComparison.Ordinal);
        Assert.Contains("dmarc findings list --org local", finding.Fix, StringComparison.Ordinal);
    }
}
