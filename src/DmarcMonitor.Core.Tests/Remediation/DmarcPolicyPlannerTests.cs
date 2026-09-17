using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// Planning a change to a DMARC record.
///
/// This is the change most capable of losing a customer's mail, so most of
/// these are about what it refuses. The plan it produces is the exact text
/// that gets written to a zone, so the rest are about that text being right
/// to the character.
/// </summary>
public sealed class DmarcPolicyPlannerTests
{
    private const string Live = "v=DMARC1; p=none; rua=mailto:dmarc@nrgtechservices.com; ruf=mailto:dmarc@nrgtechservices.com; fo=1";

    // ---- the refusals ---------------------------------------------------------

    [Fact]
    public void RefusesToJumpFromNoneToReject()
    {
        // Quarantine sends failing mail to junk, where it can be found.
        // Reject discards it. Skipping the recoverable step is how mail
        // nobody knew about disappears without a trace.
        var plan = DmarcPolicyPlanner.Advance("mortonnd.gov", Live, "reject");

        Assert.False(plan.IsSafe);
        Assert.Contains("quarantine first", plan.Blockers[0], StringComparison.Ordinal);
        Assert.Equal(Live, plan.ProposedValue);
    }

    [Fact]
    public void RefusesToEnforceOnADomainWithNoRecord()
    {
        // No record means no reports, which means no idea what sends. Every
        // legitimate sender nobody listed is affected on the first day.
        var plan = DmarcPolicyPlanner.Advance("example.com", "", "quarantine");

        Assert.False(plan.IsSafe);
        Assert.Contains("p=none first", plan.Blockers[0], StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesToOverwriteARecordThatIsNotDmarc()
    {
        // Something else lives at _dmarc on plenty of domains. Rewriting it
        // as a DMARC record deletes whatever it was for.
        var plan = DmarcPolicyPlanner.Advance("example.com", "google-site-verification=abc", "quarantine");

        Assert.False(plan.IsSafe);
        Assert.Contains("not a DMARC record", plan.Blockers[0], StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesAPolicyItDoesNotRecognise()
    {
        var plan = DmarcPolicyPlanner.Advance("example.com", Live, "block");

        Assert.False(plan.IsSafe);
    }

    // ---- what it writes ----------------------------------------------------

    [Fact]
    public void AdvancesOneRungAndKeepsEveryOtherTag()
    {
        // The rua, ruf and fo the operator set are theirs. A rewrite that
        // dropped ruf would silently stop forensic reports, and nobody would
        // connect that to a policy change.
        var plan = DmarcPolicyPlanner.Advance("mortonnd.gov", Live, "quarantine");

        Assert.True(plan.IsSafe);
        Assert.False(plan.IsNoop);
        Assert.Equal("v=DMARC1; p=quarantine; rua=mailto:dmarc@nrgtechservices.com; ruf=mailto:dmarc@nrgtechservices.com; fo=1", plan.ProposedValue);
        Assert.Equal("_dmarc.mortonnd.gov", plan.RecordName);
        Assert.Contains("from p=none to p=quarantine", plan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void PutsTheVersionFirstWhereverItWasBefore()
    {
        // RFC 7489 §6.3: v= must be first. A hand-edited record can have it
        // anywhere and still be read by lenient receivers; the rewrite must
        // not carry the fault forward.
        var plan = DmarcPolicyPlanner.Advance("example.com", "p=none; v=DMARC1; rua=mailto:x@example.com", "quarantine");

        Assert.StartsWith("v=DMARC1; p=quarantine;", plan.ProposedValue, StringComparison.Ordinal);
    }

    [Fact]
    public void ARampWritesThePercentAndFullRemovesIt()
    {
        var ramp = DmarcPolicyPlanner.Advance("example.com", "v=DMARC1; p=none", "quarantine", targetPercent: 25);
        Assert.Equal("v=DMARC1; p=quarantine; pct=25", ramp.ProposedValue);

        // pct=100 is the default, so the tag is noise; and a record carrying
        // pct=25 from the ramp must lose it when the ramp ends.
        var full = DmarcPolicyPlanner.Advance("example.com", "v=DMARC1; p=quarantine; pct=25", "quarantine", targetPercent: 100);
        Assert.Equal("v=DMARC1; p=quarantine", full.ProposedValue);
    }

    [Fact]
    public void AlreadyThereIsANoopNotARefusal()
    {
        // Running the same remediation twice must do nothing the second
        // time, and say so without alarm.
        var plan = DmarcPolicyPlanner.Advance("example.com", "v=DMARC1; p=quarantine; rua=mailto:x@example.com", "quarantine");

        Assert.True(plan.IsSafe);
        Assert.True(plan.IsNoop);
        Assert.Contains("already at p=quarantine", plan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void WarnsWhenWeakeningButDoesNotRefuse()
    {
        // Stepping back is sometimes the right call, mid-incident. It is a
        // warning so the person doing it reads it, not a blocker.
        var plan = DmarcPolicyPlanner.Advance("example.com", "v=DMARC1; p=reject", "quarantine");

        Assert.True(plan.IsSafe);
        Assert.Contains(plan.Warnings, w => w.Contains("weakens", StringComparison.Ordinal));
    }

    [Fact]
    public void WarnsWhenEnforcingWithNobodyWatching()
    {
        var plan = DmarcPolicyPlanner.Advance("example.com", "v=DMARC1; p=none", "quarantine");

        Assert.True(plan.IsSafe);
        Assert.Contains(plan.Warnings, w => w.Contains("No rua", StringComparison.Ordinal));
    }

    [Fact]
    public void CreatesAMonitoringRecordWhereThereIsNone()
    {
        var plan = DmarcPolicyPlanner.Advance("example.com", null, "none");

        Assert.True(plan.IsSafe);
        Assert.Equal("v=DMARC1; p=none; rua=mailto:dmarc@example.com", plan.ProposedValue);
        Assert.Contains(plan.Warnings, w => w.Contains("placeholder", StringComparison.Ordinal));
    }

    // ---- subdomain policy ------------------------------------------------------

    [Fact]
    public void RemovesAWeakerSubdomainPolicySoSubdomainsFollowTheDomain()
    {
        // Two live domains publish exactly this. Removing sp rather than
        // setting sp=quarantine means the next advance carries subdomains
        // with it instead of leaving them behind a second time.
        var plan = DmarcPolicyPlanner.FixSubdomainPolicy("bmcedc.com",
            "v=DMARC1; p=quarantine; pct=100; sp=none; adkim=r; aspf=r; rua=mailto:dmarc@nrgtechservices.com");

        Assert.True(plan.IsSafe);
        Assert.False(plan.IsNoop);
        Assert.Equal("v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r; rua=mailto:dmarc@nrgtechservices.com", plan.ProposedValue);
        Assert.Contains("Remove sp=none", plan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void LeavesAStrongerSubdomainPolicyAlone()
    {
        // sp=reject under p=quarantine is a choice somebody made. Removing
        // it would be the one case where this weakens something.
        var plan = DmarcPolicyPlanner.FixSubdomainPolicy("example.com", "v=DMARC1; p=quarantine; sp=reject");

        Assert.True(plan.IsNoop);
        Assert.Contains("not weaker", plan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void NoSubdomainPolicyIsNothingToFix()
    {
        var plan = DmarcPolicyPlanner.FixSubdomainPolicy("example.com", "v=DMARC1; p=quarantine");

        Assert.True(plan.IsNoop);
    }

    [Fact]
    public void CannotFixSubdomainsOfARecordThatDoesNotExist()
    {
        var plan = DmarcPolicyPlanner.FixSubdomainPolicy("example.com", "");

        Assert.False(plan.IsSafe);
    }
}
