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
        bool missing = false,
        DmarcMonitor.Core.Remediation.ServedPolicy? served = null,
        string[]? mx = null) => new()
        {
            Domain = "acme.com",
            ServedMtaSts = served,
            MxHosts = mx ?? [],
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
            new AuthorizedRange(System.Net.IPNetwork.Parse($"192.0.{i}.0/24")))],
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
    public void PlusAllIsBreakingBecauseItAuthorizesEverybody()
    {
        var findings = Assess(Published(spf: ["v=spf1 include:spf.protection.outlook.com +all"]));

        var f = Assert.Single(findings, x => x.Problem.Contains("+all", StringComparison.Ordinal));
        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("worse than having no SPF record", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void QuestionAllIsAWeaknessRatherThanABreakage()
    {
        // Neutral is not an authorization, so it is not the same as +all.
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
        //
        // Judged on the file being served rather than on the mode a report
        // remembers; see the MTA-STS section below for why the two are not
        // interchangeable.
        var findings = Assess(
            Published(served: Serving(MtaStsMode.Testing)),
            Observed(mode: "Testing"));

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

    // ---- MTA-STS, judged on the file that is served --------------------------
    //
    // This used to read the mode off the newest stored TLS report, which is
    // what senders observed when they last wrote. Two real domains were moved
    // to enforce, their files verified by fetch, and the check went on telling
    // the operator to move them to enforce. The reverse is the dangerous one: a
    // policy reverted, a Pages site down, a custom domain unbound, and it would
    // have gone on reporting enforce off a two-day-old memory.

    private static DmarcMonitor.Core.Remediation.ServedPolicy Serving(string mode, params string[] mx) =>
        new(true, new MtaStsPolicy
        {
            Mode = mode,
            Mx = mx.Length > 0 ? mx : ["acme-com.mail.protection.outlook.com"],
            Id = "20260921",
        }, null);

    [Fact]
    public void APolicyServingEnforceIsNotToldToMoveToEnforce()
    {
        // The exact false instruction this replaced.
        var findings = Assess(
            Published(served: Serving(MtaStsMode.Enforce)),
            Observed(mode: "Testing"));

        Assert.DoesNotContain(findings, f => f.Fix.Contains("Move the policy to enforce", StringComparison.Ordinal));
    }

    [Fact]
    public void ServingEnforceWhileReportsStillSayTestingIsSaidPlainlyAndCostsNothing()
    {
        var findings = Assess(
            Published(served: Serving(MtaStsMode.Enforce)),
            Observed(mode: "Testing"));

        var note = Assert.Single(findings, f => f.Record == "MTA-STS");

        Assert.Equal(HygieneSeverity.Tidy, note.Severity);
        Assert.Contains("senders act on the file they cached", note.Problem, StringComparison.Ordinal);
        Assert.StartsWith("Nothing", note.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void APolicyServingTestingIsAWeaknessWhateverTheReportsRemember()
    {
        var findings = Assess(
            Published(served: Serving(MtaStsMode.Testing)),
            Observed(mode: "Enforce"));

        var note = Assert.Single(findings, f => f.Record == "MTA-STS");

        Assert.Equal(HygieneSeverity.Weakness, note.Severity);
        Assert.Contains("being served is in testing mode", note.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void APolicyServingModeNoneIsAnnouncedAndSwitchedOff()
    {
        var findings = Assess(Published(served: Serving(MtaStsMode.None)), Observed(mode: "Enforce"));

        var note = Assert.Single(findings, f => f.Record == "MTA-STS");

        Assert.Equal(HygieneSeverity.Weakness, note.Severity);
        Assert.Contains("mode: none", note.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ARecordAnnouncingAPolicyNobodyServesIsBreaking()
    {
        // Worse than never announcing it: a sender that cached the last good
        // file keeps honouring it until max_age expires, and nothing published
        // afterwards reaches it.
        var served = DmarcMonitor.Core.Remediation.ServedPolicy.Missing("there is no host at mta-sts.acme.com");
        var findings = Assess(Published(served: served), Observed(mode: "Enforce"));

        var note = Assert.Single(findings, f => f.Record == "MTA-STS");

        Assert.Equal(HygieneSeverity.Breaking, note.Severity);
        Assert.Contains("there is no host at mta-sts.acme.com", note.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AFileThatIsServedAndDoesNotParseIsBreakingToo()
    {
        var served = new DmarcMonitor.Core.Remediation.ServedPolicy(
            true, null, "the file does not parse as an MTA-STS policy");

        var note = Assert.Single(
            Assess(Published(served: served), Observed(mode: "Enforce")), f => f.Record == "MTA-STS");

        Assert.Equal(HygieneSeverity.Breaking, note.Severity);
    }

    [Fact]
    public void WhenTheFileWasNotFetchedTheFindingSaysItCameFromTheReports()
    {
        // Never a silent fall back. An offline run judging on a memory has to
        // say that is what it did.
        var findings = Assess(Published(served: null), Observed(mode: "Testing"));

        var note = Assert.Single(findings, f => f.Record == "MTA-STS");

        Assert.Contains("The last reports from senders saw", note.Problem, StringComparison.Ordinal);
        Assert.Contains("was not fetched on this run", note.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnfetchedPolicyTheReportsCallEnforceSaysNothing()
    {
        Assert.DoesNotContain(
            Assess(Published(served: null), Observed(mode: "Enforce")), f => f.Record == "MTA-STS");
    }

    // ---- does the policy list the mail servers the domain really uses? --------

    [Fact]
    public void APolicyInEnforceThatOmitsTheDomainsMxIsRefusingItsOwnMail()
    {
        // A sender that reaches a host the policy does not name does not
        // deliver and does not fall back. Nothing in the product noticed this
        // before, and the only signal is a TLS report most domains never
        // collect.
        var findings = Assess(
            Published(
                served: Serving(MtaStsEnforce, "old-host.mail.protection.outlook.com"),
                mx: ["acme-com.mail.protection.outlook.com"]),
            Observed(mode: "Enforce"));

        var note = Assert.Single(findings, f => f.Problem.Contains("MX records point", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Breaking, note.Severity);
        Assert.Contains("acme-com.mail.protection.outlook.com", note.Problem, StringComparison.Ordinal);
        Assert.Contains("bounced", note.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSameGapInTestingModeIsAWarningRatherThanALoss()
    {
        var findings = Assess(
            Published(
                served: Serving(MtaStsMode.Testing, "old-host.mail.protection.outlook.com"),
                mx: ["acme-com.mail.protection.outlook.com"]),
            Observed(mode: "Testing"));

        var note = Assert.Single(findings, f => f.Problem.Contains("MX records point", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Weakness, note.Severity);
        Assert.Contains("before advancing the mode", note.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AWildcardCoveringTheMxProducesNoFinding()
    {
        var findings = Assess(
            Published(
                served: Serving(MtaStsEnforce, "*.mail.protection.outlook.com"),
                mx: ["acme-com.mail.protection.outlook.com"]),
            Observed(mode: "Enforce"));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("MX records point", StringComparison.Ordinal));
    }

    [Fact]
    public void NothingIsSaidAboutTheMxWhenTheLookupDidNotAnswer()
    {
        // An empty MX list means the resolver did not reply, never that the
        // domain has no mail servers, and an instruction built on it would
        // have somebody editing a policy on no evidence.
        var findings = Assess(
            Published(served: Serving(MtaStsEnforce, "anything.example"), mx: []),
            Observed(mode: "Enforce"));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("MX records point", StringComparison.Ordinal));
    }

    private const string MtaStsEnforce = MtaStsMode.Enforce;
}
