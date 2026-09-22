using DmarcMonitor.Core.Rollout;

namespace DmarcMonitor.Core.Tests.Rollout;

/// <summary>
/// Replaying stored reports against a record nobody has published.
///
/// One rule decides whether any of this is worth reading: alignment only
/// matters when the underlying mechanism AUTHENTICATED. Answering a real
/// question about a real domain by hand, I matched the SPF and DKIM domains
/// against the From domain by shape, found seventeen that looked as though
/// relaxed alignment would rescue them, and said so. All seventeen had already
/// aligned strictly and failed because SPF or DKIM had failed outright. The
/// true answer was zero.
///
/// The first test below is that mistake, written down so it cannot come back.
/// </summary>
public sealed class PolicySimulatorTests
{
    private static AuthenticationFacts Row(
        string from = "acme.com",
        string? dkimDomain = null,
        bool dkimPassed = false,
        string? spfDomain = null,
        bool spfPassed = false,
        long messages = 1,
        bool passedAsEvaluated = false,
        string sourceIp = "192.0.2.10") => new()
        {
            HeaderFrom = from,
            DkimDomain = dkimDomain,
            DkimPassed = dkimPassed,
            SpfDomain = spfDomain,
            SpfPassed = spfPassed,
            Messages = messages,
            PassedAsEvaluated = passedAsEvaluated,
            SourceIp = sourceIp,
        };

    private static ProposedPolicy Proposal(
        bool adkimStrict = false, bool aspfStrict = false, string policy = "none", int pct = 100) =>
        new() { StrictDkim = adkimStrict, StrictSpf = aspfStrict, Policy = policy, Percent = pct };

    // ---- the mistake this exists to prevent ----------------------------------

    [Fact]
    public void AnAlignedDomainOnAuthenticationThatFailedRecoversNothing()
    {
        // The seventeen. The signature named the domain exactly - it could not
        // be more aligned - and it did not verify, so no alignment setting in
        // the world makes this pass.
        var rows = new[]
        {
            Row(dkimDomain: "acme.com", dkimPassed: false,
                spfDomain: "acme.com", spfPassed: false, messages: 17),
        };

        var relaxed = PolicySimulator.Run(rows, Proposal(adkimStrict: true), Proposal(adkimStrict: false, aspfStrict: false));

        Assert.Equal(0, relaxed.NewlyPassing);
        Assert.Equal(0, relaxed.PassingAfter);
    }

    [Fact]
    public void RelaxingAlignmentRecoversOnlyWhatActuallyAuthenticated()
    {
        // Two rows that look identical if you read the domains alone. One
        // signature verified and one did not, and only the first is rescued by
        // relaxing adkim.
        var rows = new[]
        {
            Row(dkimDomain: "mail.acme.com", dkimPassed: true, messages: 10),
            Row(dkimDomain: "mail.acme.com", dkimPassed: false, messages: 10),
        };

        var strict = PolicySimulator.Run(rows, Proposal(adkimStrict: true), Proposal(adkimStrict: true));
        var relaxed = PolicySimulator.Run(rows, Proposal(adkimStrict: true), Proposal(adkimStrict: false));

        Assert.Equal(0, strict.PassingAfter);
        Assert.Equal(10, relaxed.PassingAfter);
    }

    // ---- the evaluation itself -------------------------------------------------

    [Fact]
    public void EitherMechanismIsEnough()
    {
        Assert.True(PolicySimulator.WouldPass(
            Row(dkimDomain: "acme.com", dkimPassed: true), strictDkim: true, strictSpf: true));

        Assert.True(PolicySimulator.WouldPass(
            Row(spfDomain: "acme.com", spfPassed: true), strictDkim: true, strictSpf: true));
    }

    [Fact]
    public void AMechanismThatAuthenticatedForSomebodyElseIsNotEnough()
    {
        // The vendor case: the signature verifies, over the vendor's own
        // domain. DMARC discards it, and no alignment mode changes that.
        var row = Row(dkimDomain: "mailer.vendor.example", dkimPassed: true);

        Assert.False(PolicySimulator.WouldPass(row, strictDkim: false, strictSpf: false));
    }

    [Fact]
    public void ASubdomainAlignsRelaxedAndNotStrict()
    {
        var row = Row(dkimDomain: "news.acme.com", dkimPassed: true);

        Assert.True(PolicySimulator.WouldPass(row, strictDkim: false, strictSpf: false));
        Assert.False(PolicySimulator.WouldPass(row, strictDkim: true, strictSpf: false));
    }

    [Fact]
    public void TheTwoMechanismsAreAlignedIndependently()
    {
        // aspf=s must not be able to reject a pass that DKIM earned.
        var row = Row(dkimDomain: "acme.com", dkimPassed: true,
                      spfDomain: "bounce.vendor.example", spfPassed: true);

        Assert.True(PolicySimulator.WouldPass(row, strictDkim: false, strictSpf: true));
    }

    [Fact]
    public void AnEmptyDomainNeverAligns()
    {
        // Receivers really do emit <dkim><domain/><result/></dkim>.
        Assert.False(PolicySimulator.WouldPass(
            Row(dkimDomain: "", dkimPassed: true), strictDkim: false, strictSpf: false));

        Assert.False(PolicySimulator.WouldPass(
            Row(dkimDomain: null, dkimPassed: true), strictDkim: false, strictSpf: false));
    }

    // ---- the cost of a change ---------------------------------------------------

    [Fact]
    public void TighteningAlignmentNamesWhatItWouldCostAndWho()
    {
        var rows = new[]
        {
            Row(dkimDomain: "news.acme.com", dkimPassed: true, messages: 40,
                passedAsEvaluated: true, sourceIp: "198.51.100.7"),
            Row(dkimDomain: "acme.com", dkimPassed: true, messages: 500, passedAsEvaluated: true),
        };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal(adkimStrict: true));

        Assert.Equal(40, outcome.NewlyFailing);
        Assert.False(outcome.CostsNothing);

        var source = Assert.Single(outcome.Sources);
        Assert.Equal("198.51.100.7", source.SourceIp);
        Assert.Equal(40, source.NewlyFailing);
        Assert.Equal("news.acme.com", source.Signs);
    }

    [Fact]
    public void AChangeThatCostsNothingSaysSo()
    {
        // The answer that unblocks somebody, and the one a tool that only
        // warns can never give.
        var rows = new[] { Row(dkimDomain: "acme.com", dkimPassed: true, messages: 46, passedAsEvaluated: true) };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal(aspfStrict: true));

        Assert.True(outcome.CostsNothing);
        Assert.Equal(0, outcome.NewlyFailing);
    }

    [Fact]
    public void PassingMailIsSplitByWhichMechanismIsCarryingIt()
    {
        // What answers "can this domain go to -all". Mail resting on DKIM does
        // not care what the SPF all-mechanism says.
        var rows = new[]
        {
            Row(dkimDomain: "acme.com", dkimPassed: true, messages: 46, passedAsEvaluated: true),
            Row(spfDomain: "acme.com", spfPassed: true, messages: 5, passedAsEvaluated: true),
            Row(dkimDomain: "acme.com", dkimPassed: true,
                spfDomain: "acme.com", spfPassed: true, messages: 9, passedAsEvaluated: true),
        };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal());

        Assert.Equal(46, outcome.PassingOnDkimOnly);
        Assert.Equal(5, outcome.PassingOnSpfOnly);
        Assert.Equal(9, outcome.PassingOnBoth);
    }

    // ---- what the policy does to what fails ---------------------------------------

    [Fact]
    public void MovingToQuarantineCountsTheMailThatWouldBeJunked()
    {
        var rows = new[]
        {
            Row(dkimDomain: "acme.com", dkimPassed: true, messages: 900, passedAsEvaluated: true),
            Row(messages: 85),
        };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal(policy: "quarantine"));

        Assert.Equal(85, outcome.WouldBeActedOn);
        Assert.Equal(0, outcome.WouldBeDeliveredAnyway);
    }

    [Fact]
    public void PctLeavesTheRestDelivered()
    {
        var rows = new[] { Row(messages: 100) };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal(policy: "reject", pct: 25));

        Assert.Equal(25, outcome.WouldBeActedOn);
        Assert.Equal(75, outcome.WouldBeDeliveredAnyway);
    }

    [Fact]
    public void AtPNoneNothingIsActedOnHoweverMuchFails()
    {
        var outcome = PolicySimulator.Run([Row(messages: 100)], Proposal(), Proposal(policy: "none"));

        Assert.Equal(0, outcome.WouldBeActedOn);
        Assert.Equal(100, outcome.WouldBeDeliveredAnyway);
    }

    // ---- refusing to invent -------------------------------------------------------

    [Fact]
    public void AMessageThisRowCannotExplainIsSetAsideRatherThanCountedAsACost()
    {
        // A message can carry several signatures and the store keeps one of
        // them. Where the row reaches the opposite verdict to the receiver,
        // the receiver is right and the row cannot be trusted to say what a
        // change would do to it either.
        //
        // Real, and the first run against live data found it: nine of 929
        // messages on ndaco.org, all Microsoft 365 mail carrying a tenant
        // signature alongside the customer's own. Counted as a cost, they made
        // moving that domain to p=reject look as though it would lose mail
        // that it cannot lose - p= does not decide what passes.
        var rows = new[] { Row(dkimDomain: "vendor.example", dkimPassed: true, messages: 12, passedAsEvaluated: true) };

        var outcome = PolicySimulator.Run(rows, Proposal(), Proposal(policy: "reject"));

        Assert.Equal(12, outcome.PassingNow);
        Assert.Equal(12, outcome.Unexplained);
        Assert.Equal(0, outcome.Modelled);
        Assert.Equal(0, outcome.NewlyFailing);
        Assert.True(outcome.CostsNothing);
    }

    [Fact]
    public void ChangingOnlyThePolicyNeverCostsAnything()
    {
        // p= decides what happens to mail that fails, never whether it fails.
        // A simulator that measured from the receivers' verdicts rather than
        // from the record in force reported a cost here, which is the bug this
        // pins down.
        var rows = new[]
        {
            Row(dkimDomain: "acme.com", dkimPassed: true, messages: 819, passedAsEvaluated: true),
            Row(messages: 110),
        };

        var outcome = PolicySimulator.Run(rows, Proposal(policy: "quarantine"), Proposal(policy: "reject"));

        Assert.Equal(0, outcome.NewlyFailing);
        Assert.Equal(0, outcome.NewlyPassing);
        Assert.True(outcome.CostsNothing);
        Assert.Equal(110, outcome.WouldBeActedOn);
    }

    [Fact]
    public void NoRowsIsAnEmptyAnswerRatherThanAThrow()
    {
        var outcome = PolicySimulator.Run([], Proposal(), Proposal(policy: "reject"));

        Assert.Equal(0, outcome.Messages);
        Assert.True(outcome.CostsNothing);
        Assert.Empty(outcome.Sources);
    }

    [Fact]
    public void NullsAreRefusedRatherThanTreatedAsEmpty()
    {
        Assert.Throws<ArgumentNullException>(() => PolicySimulator.Run(null!, Proposal(), Proposal()));
        Assert.Throws<ArgumentNullException>(() => PolicySimulator.Run([], Proposal(), null!));
        Assert.Throws<ArgumentNullException>(() => PolicySimulator.Run([], null!, Proposal()));
        Assert.Throws<ArgumentNullException>(() => PolicySimulator.WouldPass(null!, false, false));
    }
}
