using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// What a domain's published records get wrong.
///
/// An operator acts on these by editing a customer's DNS, so a wrong finding
/// here does not waste time, it breaks a business's mail. The rule throughout
/// is that anything which cannot be established from the record is left unsaid
/// rather than guessed at, and the tests below are mostly about the things it
/// must refuse to claim.
/// </summary>
public sealed class DnsHygieneTests
{
    private static PublishedRecords Published(
        string[]? spf = null,
        string? dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        string? mtaSts = "v=STSv1; id=1",
        string? tlsRpt = "v=TLSRPTv1; rua=mailto:tls@example.com",
        string[]? dead = null,
        int lookups = 0,
        bool failed = false,
        bool missing = false) => new()
        {
            Domain = "acme.com",
            SpfRecords = spf ?? ["v=spf1 include:spf.protection.outlook.com -all"],
            DmarcRecord = dmarc,
            MtaStsRecord = mtaSts,
            TlsRptRecord = tlsRpt,
            DeadIncludes = dead ?? [],
            SpfLookups = lookups,
            LookupFailed = failed,
            DomainDoesNotExist = missing,
        };

    private static ObservedSending Observed(
        string mode = "Enforce",
        bool tls = true,
        int windowDays = 90,
        IReadOnlyList<IncludeUsage>? includes = null) =>
        new()
        {
            MtaStsMode = mode,
            TlsReportsArriving = tls,
            Messages = 1000,
            WindowDays = windowDays,
            Includes = includes ?? [],
        };

    private static IncludeUsage Include(string target, long messages, int ranges = 4) => new()
    {
        Target = target,
        Messages = messages,
        Ranges = [.. Enumerable.Range(0, ranges).Select(i =>
            new AuthorisedRange(System.Net.IPNetwork.Parse($"192.0.{i}.0/24")))],
    };

    private static IReadOnlyList<HygieneFinding> Assess(
        PublishedRecords? p = null, ObservedSending? o = null) =>
        DnsHygiene.Assess(p ?? Published(), o ?? Observed());

    // ---- the refusals ---------------------------------------------------------

    [Fact]
    public void ALookupThatFailedIsNotReportedAsRecordsThatAreMissing()
    {
        // The most dangerous confusion available here. Told "no DMARC record"
        // for a domain that has one, somebody publishes a second over the top
        // of the first, and now there are two.
        var findings = Assess(Published(failed: true));

        var only = Assert.Single(findings);
        Assert.Contains("could not be read", only.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain(findings, f => f.Record == "DMARC");
        Assert.DoesNotContain(findings, f => f.Record == "SPF");
    }

    [Fact]
    public void ADomainThatDoesNotExistIsNotADomainWithNoRecords()
    {
        // NXDOMAIN and "publishes no TXT records" both arrive as an empty
        // answer section, so a mistyped customer domain used to come back with
        // a full list of weaknesses and instructions to publish records at an
        // apex nobody owns - confident, detailed and entirely fictional.
        var findings = Assess(Published(missing: true));

        var only = Assert.Single(findings);
        Assert.Contains("no domain called", only.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain(findings, f => f.Record is "SPF" or "DMARC" or "MTA-STS" or "TLS-RPT");
    }

    [Fact]
    public void SaysNothingAboutARecordItCannotParse()
    {
        // A TXT record that is not SPF is not a broken SPF record, and
        // recommending changes to it would have somebody edit something else.
        var findings = Assess(Published(spf: ["google-site-verification=abc123"]));

        Assert.DoesNotContain(findings, f => f.Record == "SPF" && f.Problem.Contains("lookup", StringComparison.Ordinal));
    }

    [Fact]
    public void ACleanDomainIsToldNothing()
    {
        // A check that always finds something is a check nobody runs twice.
        Assert.Empty(Assess());
    }

    // ---- SPF ------------------------------------------------------------------

    [Fact]
    public void MoreThanOneSpfRecordIsBreakingRatherThanUntidy()
    {
        // Two records is a permerror, and a permerror is not a pass: SPF stops
        // working for every sender, including the legitimate ones.
        var findings = Assess(Published(spf:
        [
            "v=spf1 include:spf.protection.outlook.com -all",
            "v=spf1 include:sendgrid.net -all",
        ]));

        var f = Assert.Single(findings, x => x.Record == "SPF" && x.Problem.Contains("2 SPF records", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("RFC 7208", f.Reference, StringComparison.Ordinal);
    }

    [Fact]
    public void OverTheLookupLimitIsBreaking()
    {
        var findings = Assess(Published(lookups: 12));

        var f = Assert.Single(findings, x => x.Problem.Contains("12 DNS lookups", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
    }

    [Fact]
    public void NearTheLookupLimitIsAWarningRatherThanABreakage()
    {
        // Nothing is wrong today. The point is that the next service added
        // breaks it, and that is worth knowing before rather than after.
        var findings = Assess(Published(lookups: 9));

        var f = Assert.Single(findings, x => x.Problem.Contains("9 of the 10", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
    }

    [Fact]
    public void WellUnderTheLimitSaysNothing()
    {
        Assert.DoesNotContain(Assess(Published(lookups: 4)), f => f.Problem.Contains("lookup", StringComparison.Ordinal));
    }

    [Fact]
    public void UsesTheResolvedCountRatherThanTheTermsInTheRecord()
    {
        // One include can be a dozen lookups once followed. Counting the terms
        // in the record would tell a domain sitting over the limit that it
        // uses two, which is wrong in the direction that lets mail quietly
        // stop authenticating.
        var findings = Assess(Published(
            spf: ["v=spf1 include:a.example include:b.example -all"],
            lookups: 14));

        Assert.Contains(findings, f => f.Problem.Contains("14 DNS lookups", StringComparison.Ordinal));
    }

    [Fact]
    public void PlusAllIsBreakingBecauseItAuthorisesEverybody()
    {
        var findings = Assess(Published(spf: ["v=spf1 include:spf.protection.outlook.com +all"]));

        var f = Assert.Single(findings, x => x.Problem.Contains("+all", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("worse than having no SPF record", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void QuestionAllIsAWeaknessRatherThanABreakage()
    {
        // Neutral is not an authorisation, so it is not the same as +all.
        var findings = Assess(Published(spf: ["v=spf1 include:spf.protection.outlook.com ?all"]));

        Assert.Equal(HygieneSeverity.Weakness,
            Assert.Single(findings, x => x.Problem.Contains("?all", StringComparison.Ordinal)).Severity);
    }

    [Fact]
    public void TildeAllIsAcceptedWithoutComment()
    {
        // Softfail is the normal position during a rollout and telling
        // everybody to change it is how the check becomes noise.
        Assert.DoesNotContain(
            Assess(Published(spf: ["v=spf1 include:spf.protection.outlook.com ~all"])),
            f => f.Problem.Contains("all", StringComparison.Ordinal));
    }

    [Fact]
    public void ARecordWithNoAllMechanismSaysSo()
    {
        var findings = Assess(Published(spf: ["v=spf1 include:spf.protection.outlook.com"]));

        Assert.Contains(findings, f => f.Problem.Contains("no all mechanism", StringComparison.Ordinal));
    }

    [Fact]
    public void ADeadIncludeIsNamedSoItCanBeDeleted()
    {
        var findings = Assess(Published(dead: ["spf.retired-provider.example"]));

        var f = Assert.Single(findings, x => x.Problem.Contains("spf.retired-provider.example", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Tidy, f.Severity);
        Assert.Contains("Remove include:spf.retired-provider.example", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePtrMechanismIsFlagged()
    {
        var findings = Assess(Published(spf: ["v=spf1 ptr -all"]));

        Assert.Contains(findings, f => f.Problem.Contains("ptr mechanism", StringComparison.Ordinal));
    }

    // ---- includes: evidence, never an instruction -----------------------------

    [Fact]
    public void AnIncludeNothingHasComeFromIsRaisedWithTheRealSpanOfEvidence()
    {
        var findings = Assess(o: Observed(windowDays: 43, includes: [Include("_spf.intacct.com", 0)]));

        var f = Assert.Single(findings, x => x.Problem.Contains("_spf.intacct.com", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Tidy, f.Severity);
        Assert.Contains("43 days of reports held", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ItNeverTellsAnybodyToDeleteAnInclude()
    {
        // The finding that could break a business's mail if it were phrased as
        // an instruction. A quiet include is evidence to check, not a verdict.
        var findings = Assess(o: Observed(windowDays: 90, includes: [Include("_spf.intacct.com", 0)]));

        var f = Assert.Single(findings, x => x.Problem.Contains("_spf.intacct.com", StringComparison.Ordinal));
        Assert.Contains("Confirm the business no longer uses", f.Fix, StringComparison.Ordinal);
        Assert.Contains("evidence rather than an instruction", f.Fix, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove include", f.Fix, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(17)]
    [InlineData(29)]
    public void SaysNothingAboutAnIncludeOnTooLittleHistory(int days)
    {
        // Two live domains hold 17 and 2 days. A service that bills monthly
        // has sent nothing in either, and saying so would be inventing the
        // evidence rather than reporting it.
        var findings = Assess(o: Observed(windowDays: days, includes: [Include("_spf.intacct.com", 0)]));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("_spf.intacct.com", StringComparison.Ordinal));
    }

    [Fact]
    public void AnIncludeThatIsCarryingMailIsNotMentioned()
    {
        var findings = Assess(o: Observed(
            windowDays: 90,
            includes: [Include("spf.protection.outlook.com", 4_000)]));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("spf.protection.outlook.com", StringComparison.Ordinal));
    }

    [Fact]
    public void AnIncludeThatResolvedToNothingIsLeftToTheDeadIncludeCheck()
    {
        // Zero ranges means it was never resolved, not that it is unused.
        // Reporting it here as "no mail seen" would be a second finding about
        // the same thing, worded as though it had been measured.
        var findings = Assess(o: Observed(windowDays: 90, includes: [Include("gone.example", 0, ranges: 0)]));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("no mail has been seen", StringComparison.Ordinal));
    }

    [Fact]
    public void NamesTheServiceSoSomebodyKnowsWhatTheyAreBeingAskedAbout()
    {
        // "_spf.intacct.com" is not a question a business owner can answer.
        // "intacct.com" is.
        var findings = Assess(o: Observed(windowDays: 90, includes: [Include("_spf.intacct.com", 0)]));

        Assert.Contains("(intacct.com)",
            Assert.Single(findings, f => f.Problem.Contains("_spf.intacct", StringComparison.Ordinal)).Problem,
            StringComparison.Ordinal);
    }

    // ---- DMARC ----------------------------------------------------------------

    [Fact]
    public void NoDmarcRecordIsTheFirstThingToFix()
    {
        var findings = Assess(Published(dmarc: null));

        Assert.Contains(findings, f => f.Record == "DMARC" && f.Problem.Contains("No DMARC record", StringComparison.Ordinal));
    }

    [Fact]
    public void ADmarcRecordWithNoRuaIsFlaggedBecauseNothingIsSeen()
    {
        var findings = Assess(Published(dmarc: "v=DMARC1; p=reject"));

        Assert.Contains(findings, f => f.Problem.Contains("no rua address", StringComparison.Ordinal));
    }

    [Fact]
    public void PartialEnforcementIsNamedWithItsNumbers()
    {
        // pct is the tag that makes a domain look enforcing in every summary
        // while most failing mail is delivered anyway.
        var findings = Assess(Published(dmarc: "v=DMARC1; p=reject; pct=20; rua=mailto:x@example.com"));

        var f = Assert.Single(findings, x => x.Problem.Contains("pct=20", StringComparison.Ordinal));
        Assert.Contains("80% is delivered", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ASubdomainPolicyWeakerThanTheDomainIsAHole()
    {
        // Found on two live domains: p=quarantine with sp=none, so the domain
        // is protected and everything under it is not.
        var findings = Assess(Published(dmarc: "v=DMARC1; p=quarantine; sp=none; rua=mailto:x@example.com"));

        var f = Assert.Single(findings, x => x.Problem.Contains("sp=none", StringComparison.Ordinal));
        Assert.Contains("more leniently", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ASubdomainPolicyStrongerThanTheDomainIsNotComplainedAbout()
    {
        Assert.DoesNotContain(
            Assess(Published(dmarc: "v=DMARC1; p=none; sp=reject; rua=mailto:x@example.com")),
            f => f.Problem.Contains("sp=", StringComparison.Ordinal));
    }

    [Fact]
    public void AnAbsentSpIsNotAFindingBecauseSubdomainsInheritIt()
    {
        Assert.DoesNotContain(
            Assess(Published(dmarc: "v=DMARC1; p=reject; rua=mailto:x@example.com")),
            f => f.Problem.Contains("sp=", StringComparison.Ordinal));
    }

    // ---- transport ------------------------------------------------------------

    [Fact]
    public void MtaStsInTestingModeIsAWeaknessRatherThanAbsence()
    {
        // The record exists, so "no policy published" would be wrong. What is
        // wrong is that it enforces nothing.
        var findings = Assess(o: Observed(mode: "Testing"));

        var f = Assert.Single(findings, x => x.Record == "MTA-STS");
        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("delivers the mail anyway", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void NoMtaStsRecordIsATidyRatherThanAWeakness()
    {
        // Worth doing, and not the thing to interrupt somebody about while a
        // domain is being forged.
        var findings = Assess(Published(mtaSts: null));

        Assert.Equal(HygieneSeverity.Tidy, Assert.Single(findings, f => f.Record == "MTA-STS").Severity);
    }

    [Fact]
    public void TlsReportsArrivingWithNoRecordPublishedSaysWhereTheyAreGoing()
    {
        // They are reaching somebody. If it is not us, somebody else is
        // receiving this customer's transport reports.
        var findings = Assess(Published(tlsRpt: null), Observed(tls: true));

        Assert.Contains("somewhere other than here",
            Assert.Single(findings, f => f.Record == "TLS-RPT").Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void NoTlsReportsAndNoRecordIsJustAMissingRecord()
    {
        var findings = Assess(Published(tlsRpt: null), Observed(tls: false));

        Assert.Contains("nobody reports failed",
            Assert.Single(findings, f => f.Record == "TLS-RPT").Problem, StringComparison.Ordinal);
    }

    // ---- ordering and shape ---------------------------------------------------

    [Fact]
    public void TheWorstFindingComesFirst()
    {
        var findings = Assess(Published(
            spf: ["v=spf1 +all"],
            dmarc: "v=DMARC1; p=reject; pct=50; rua=mailto:x@example.com",
            mtaSts: null));

        Assert.Equal(HygieneSeverity.Breaking, findings[0].Severity);
    }

    [Fact]
    public void EveryFindingSaysWhatToDoAboutIt()
    {
        // A finding without a fix is a complaint.
        var findings = Assess(Published(
            spf: ["v=spf1 ptr ?all"], dmarc: "v=DMARC1; p=none", mtaSts: null, tlsRpt: null,
            dead: ["dead.example"], lookups: 11));

        Assert.NotEmpty(findings);
        Assert.All(findings, f =>
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Problem));
            Assert.False(string.IsNullOrWhiteSpace(f.Fix));
            Assert.False(string.IsNullOrWhiteSpace(f.Record));
        });
    }

    [Fact]
    public void RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => DnsHygiene.Assess(null!, Observed()));
        Assert.Throws<ArgumentNullException>(() => DnsHygiene.Assess(Published(), null!));
    }
}
