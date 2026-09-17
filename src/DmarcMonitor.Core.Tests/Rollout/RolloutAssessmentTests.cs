using DmarcMonitor.Core.Rollout;

namespace DmarcMonitor.Core.Tests.Rollout;

/// <summary>
/// What a domain needs, and how urgently.
///
/// This decides what an operator sees first, so getting the ordering wrong is
/// worse than getting a number wrong: a triage list that cries wolf about a
/// planned rollout is a list somebody stops reading, and then the real
/// emergency is missed too.
/// </summary>
public sealed class RolloutAssessmentTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 17, 12, 0, 0, TimeSpan.Zero);

    private static DomainState State(
        string policy = "none",
        long messages = 100,
        long passing = 100,
        int failingSources = 0,
        int? lastReportDaysAgo = 1,
        int? baselineStartedDaysAgo = null,
        int baselineDays = 14,
        string target = "reject") => new()
        {
            Domain = "acme.com",
            Policy = policy,
            PolicyTarget = target,
            Messages = messages,
            Passing = passing,
            FailingSources = failingSources,
            LastReport = lastReportDaysAgo is null ? null : Now.AddDays(-lastReportDaysAgo.Value),
            BaselineStarted = baselineStartedDaysAgo is null ? null : Now.AddDays(-baselineStartedDaysAgo.Value),
            BaselineDays = baselineDays,
            Now = Now,
        };

    // ---- the case that prompted this ----------------------------------------

    [Fact]
    public void ADeliberateBaselineStillRunningIsOnTrackRatherThanOutstandingWork()
    {
        // A domain on day four of a planned two-week baseline is doing exactly
        // what it should. Reporting it as needing work is how the list becomes
        // noise, and then the domain actually losing mail gets skimmed past.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", messages: 1000, passing: 994, failingSources: 3, baselineStartedDaysAgo: 4));

        Assert.Equal(TriageLevel.OnTrack, verdict.Level);
        Assert.Contains("Day 4 of a 14-day baseline", verdict.Headline, StringComparison.Ordinal);
        Assert.Contains("10 day(s)", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ABaselineSaysWhatTheFailuresAreForRatherThanTreatingThemAsAProblem()
    {
        // Finding failing senders is the POINT of the window, not a symptom of
        // something going wrong in it.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", messages: 100, passing: 90, failingSources: 2, baselineStartedDaysAgo: 2));

        Assert.Contains("what this window is for", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ABaselineWithNothingFailingSaysSo()
    {
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", baselineStartedDaysAgo: 5));

        Assert.Contains("Nothing failing so far", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void NamesTheTargetPolicyRatherThanAssumingReject()
    {
        // A domain deliberately heading to quarantine and stopping there is a
        // real choice, and telling its operator it should go to reject is
        // advice they did not ask for.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", baselineStartedDaysAgo: 3, target: "quarantine"));

        Assert.Contains("p=quarantine", verdict.Headline, StringComparison.Ordinal);
        Assert.DoesNotContain("p=reject", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ABaselineThatHasFinishedStopsBeingAnExcuse()
    {
        // Day 30 of a 14-day baseline is not a rollout, it is a domain that
        // was started and forgotten. It says so, with the day count, rather
        // than reading identically to one that was never begun.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", messages: 100, passing: 80, failingSources: 2, baselineStartedDaysAgo: 30));

        Assert.NotEqual(TriageLevel.OnTrack, verdict.Level);
        Assert.Contains("Baseline finished", verdict.Headline, StringComparison.Ordinal);
        Assert.Contains("day 30", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainAtPNoneWithNoBaselineIsNotGivenTheBenefitOfTheDoubt()
    {
        // No baseline recorded means nobody planned this. Treating it as an
        // intentional rollout would hide every neglected domain.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", messages: 100, passing: 80, failingSources: 2));

        Assert.NotEqual(TriageLevel.OnTrack, verdict.Level);
    }

    // ---- ordering: the worst true statement wins ----------------------------

    [Fact]
    public void MailBeingLostNowOutranksEverythingExceptStaleData()
    {
        var verdict = RolloutAssessment.Assess(
            State(policy: "reject", messages: 1000, passing: 800, failingSources: 4));

        Assert.Equal(TriageLevel.Urgent, verdict.Level);
        Assert.Contains("refused", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysJunkedRatherThanRefusedUnderQuarantine()
    {
        // The difference a client will ask about: junked mail can be retrieved,
        // refused mail is gone.
        var verdict = RolloutAssessment.Assess(
            State(policy: "quarantine", messages: 1000, passing: 800, failingSources: 4));

        Assert.Contains("sent to junk", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void StaleDataOutranksEvenMailBeingLost()
    {
        // Every other judgement is computed from reports. If those stopped
        // arriving a week ago, the rest of this page is describing the past.
        var verdict = RolloutAssessment.Assess(
            State(policy: "reject", messages: 1000, passing: 500, failingSources: 9, lastReportDaysAgo: 10));

        Assert.Equal(TriageLevel.Act, verdict.Level);
        Assert.Contains("No reports for 10 days", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ABaselineDoesNotSuppressStaleData()
    {
        // A rollout nobody is receiving reports for is not on track, whatever
        // the calendar says.
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", baselineStartedDaysAgo: 3, lastReportDaysAgo: 9));

        Assert.NotEqual(TriageLevel.OnTrack, verdict.Level);
        Assert.Contains("No reports", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainThatNeverReportedIsFlagged()
    {
        var verdict = RolloutAssessment.Assess(State(lastReportDaysAgo: null));

        Assert.Equal(TriageLevel.Watch, verdict.Level);
        Assert.Contains("rua", verdict.Headline, StringComparison.Ordinal);
    }

    // ---- the ordinary states ------------------------------------------------

    [Fact]
    public void ACleanEnforcingDomainNeedsNothing()
    {
        var verdict = RolloutAssessment.Assess(State(policy: "reject", messages: 1000, passing: 1000));

        Assert.Equal(TriageLevel.Fine, verdict.Level);
        Assert.Empty(verdict.Headline);
    }

    [Fact]
    public void AQuarantiningDomainHeadingForRejectIsToldSo()
    {
        var verdict = RolloutAssessment.Assess(
            State(policy: "quarantine", messages: 1000, passing: 1000, target: "reject"));

        Assert.Equal(TriageLevel.Watch, verdict.Level);
        Assert.Contains("Ready to move to p=reject", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void AQuarantiningDomainThatIsMeantToStopThereIsLeftAlone()
    {
        var verdict = RolloutAssessment.Assess(
            State(policy: "quarantine", messages: 1000, passing: 1000, target: "quarantine"));

        Assert.Equal(TriageLevel.Fine, verdict.Level);
    }

    [Fact]
    public void ACleanDomainAtPNoneIsReadyToAdvance()
    {
        var verdict = RolloutAssessment.Assess(State(policy: "none", messages: 1000, passing: 1000));

        Assert.Equal(TriageLevel.Act, verdict.Level);
        Assert.Contains("Ready to move", verdict.Headline, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(89, TriageLevel.Act)]
    [InlineData(95, TriageLevel.Watch)]
    public void HowBadAPNoneDomainIsDependsOnHowMuchWouldBreak(int passRate, TriageLevel expected)
    {
        var verdict = RolloutAssessment.Assess(
            State(policy: "none", messages: 100, passing: passRate, failingSources: 2));

        Assert.Equal(expected, verdict.Level);
    }

    // ---- mail being lost while the rate looks healthy -------------------------

    [Fact]
    public void AnEnforcingDomainStillLosingMailIsNeverSilent()
    {
        // nrgtechservices.com on the live data: 2,364 messages, 98.2% passing,
        // p=reject. That is 42 messages refused outright, and the row said
        // nothing at all because the pass rate cleared the threshold. Silence
        // reads as nothing happening, and noticing this is what an MSP is
        // being paid for.
        var verdict = RolloutAssessment.Assess(
            State(policy: "reject", messages: 2364, passing: 2322, failingSources: 6));

        Assert.NotEqual(TriageLevel.Fine, verdict.Level);
        Assert.False(string.IsNullOrWhiteSpace(verdict.Headline));
        Assert.Contains("42 message(s)", verdict.Headline, StringComparison.Ordinal);
        Assert.Contains("refused outright", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysTheCountRatherThanLeavingItAsAPercentage()
    {
        // "98.2% passing" is not something anybody acts on. "42 refused" is.
        var verdict = RolloutAssessment.Assess(
            State(policy: "reject", messages: 2364, passing: 2322, failingSources: 6));

        Assert.Contains("42", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void QuarantiningIsNotCalledCleanWhileMailIsBeingJunked()
    {
        // bmcedc.com on the live data: 95.8% passing, which cleared the
        // threshold, and 86 messages went to junk. "Quarantining cleanly" is
        // a claim the numbers do not support.
        var verdict = RolloutAssessment.Assess(
            State(policy: "quarantine", messages: 2067, passing: 1981, failingSources: 30));

        Assert.DoesNotContain("cleanly", verdict.Headline, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("86 message(s)", verdict.Headline, StringComparison.Ordinal);
        Assert.Contains("sent to junk", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void AdvancingIsPresentedAsADecisionWhileAnythingIsStillFailing()
    {
        // Moving that domain to p=reject turns 86 junked messages into 86
        // bounced ones. That is a choice somebody should make deliberately,
        // not a formality the page recommends.
        var verdict = RolloutAssessment.Assess(
            State(policy: "quarantine", messages: 2067, passing: 1981, failingSources: 30));

        Assert.Contains("would be refused instead", verdict.Headline, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEnforcingDomainWithNothingFailingStaysQuiet()
    {
        // The other side of it: a page that talks about every domain is a
        // page nobody reads.
        var verdict = RolloutAssessment.Assess(
            State(policy: "reject", messages: 5000, passing: 5000, target: "reject"));

        Assert.Equal(TriageLevel.Fine, verdict.Level);
        Assert.Empty(verdict.Headline);
    }

    [Fact]
    public void SilenceNamesBothCausesRatherThanBlamingTheCustomersDns()
    {
        // Today proved the point: four domains looked as though their records
        // had been removed, and collection had stopped instead. Naming only
        // the customer's DNS sends an operator to the wrong place.
        var verdict = RolloutAssessment.Assess(State(lastReportDaysAgo: 61));

        Assert.Contains("collection stopped", verdict.Headline, StringComparison.Ordinal);
        Assert.Contains("record changed", verdict.Headline, StringComparison.Ordinal);
    }

    // ---- guards -------------------------------------------------------------

    [Fact]
    public void EveryVerdictExceptFineExplainsItself()
    {
        // A level with no sentence is a coloured dot an operator has to guess
        // at, which is the thing this page exists to replace.
        DomainState[] states =
        [
            State(lastReportDaysAgo: null),
            State(lastReportDaysAgo: 9),
            State(policy: "reject", messages: 100, passing: 50, failingSources: 2),
            State(policy: "none", baselineStartedDaysAgo: 2),
            State(policy: "none", messages: 100, passing: 80, failingSources: 1),
            State(policy: "none", messages: 100, passing: 100),
            State(policy: "quarantine", messages: 100, passing: 100),
        ];

        foreach (var state in states)
        {
            var verdict = RolloutAssessment.Assess(state);
            if (verdict.Level != TriageLevel.Fine)
            {
                Assert.False(string.IsNullOrWhiteSpace(verdict.Headline), $"{state.Policy} produced a bare level");
            }
        }
    }

    [Fact]
    public void NeverDividesByZeroForADomainThatSentNothing()
    {
        var verdict = RolloutAssessment.Assess(State(policy: "reject", messages: 0, passing: 0));
        Assert.Equal(TriageLevel.Fine, verdict.Level);
    }

    [Fact]
    public void RejectsANullState() =>
        Assert.Throws<ArgumentNullException>(() => RolloutAssessment.Assess(null!));
}
