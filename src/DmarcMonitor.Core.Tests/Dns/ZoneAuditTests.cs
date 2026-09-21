using System.Security.Cryptography;
using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Judging a zone file against live DNS and against the reports.
///
/// Every case here is one that was found by hand against a real estate of
/// sixteen domains before any of this existed, with the names and the key
/// material replaced. The point of writing them down is that all of them are
/// invisible from a control panel: a record that reads correctly and is not
/// evaluated, a selector that resolves to nothing, a version tag off by one
/// character, a name server for a provider the domain left two years ago.
///
/// The tests that matter most are the ones asserting silence. This runs
/// against customer DNS and an operator acts on what it says, so the whole
/// design is that anything the evidence does not establish is left unsaid -
/// and it is far easier to notice a missing finding than a confident wrong
/// one.
/// </summary>
public sealed class ZoneAuditTests
{
    // Generated once. A key is a few hundred milliseconds and these tests are
    // about what is concluded from a key's size, not about RSA.
    private static readonly string Key2048 = Key(2048);
    private static readonly string Key1024 = Key(1024);
    private static readonly string Key512 = Key(512);

    private static string Key(int bits)
    {
        using var rsa = RSA.Create(bits);
        return $"v=DKIM1; k=rsa; p={Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())}";
    }

    private static ParsedZone Zone(string body) =>
        ZoneFile.Parse("$ORIGIN example.com.\n" + body);

    private static IReadOnlyList<ZoneFinding> Assess(string body, ZoneEvidence? evidence = null) =>
        ZoneAudit.Assess(Zone(body), evidence ?? new ZoneEvidence());

    private static ZoneEvidence Live(
        PublishedRecords? published = null,
        IReadOnlyList<string>? delegation = null,
        Dictionary<string, SelectorEvidence>? selectors = null,
        IReadOnlyList<string>? signing = null,
        int windowDays = 0)
        => new()
        {
            Live = published ?? new PublishedRecords { Domain = "example.com" },
            Delegation = delegation ?? [],
            Selectors = selectors ?? new Dictionary<string, SelectorEvidence>(StringComparer.OrdinalIgnoreCase),
            SeenSigning = signing ?? [],
            ReportsRead = windowDays > 0,
            ReportWindowDays = windowDays,
        };

    private static SelectorEvidence Resolved(string selector, string? record, bool seenSigning = false) => new()
    {
        Selector = selector,
        LiveRecords = record is null ? [] : [record],
        LiveKey = DkimKey.Choose(selector, record is null ? [] : [record]),
        SeenSigning = seenSigning,
    };

    // ---- SPF ------------------------------------------------------------------

    [Fact]
    public void ARecordThatReadsAsSpfWithoutTheVersionPrefixIsNotReportedAsAMissingRecord()
    {
        // The finding this whole feature exists for. The tool used to say "No
        // SPF record is published", which is true and useless: the operator
        // publishes a second record beside the one already there.
        var findings = Assess("""
            @	3600	IN	TXT	"include:spf.protection.outlook.com include:amazonses.com -all"
            """);

        var spf = Assert.Single(findings, f => f.Record == "SPF");

        Assert.Equal(HygieneSeverity.Breaking, spf.Severity);
        Assert.Contains("v=spf1", spf.Problem, StringComparison.Ordinal);
        Assert.Contains("include:spf.protection.outlook.com", spf.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void TheFixIsTheSameRecordWithThePrefixRatherThanASecondRecord()
    {
        var findings = Assess("""
            @	3600	IN	TXT	"include:spf.protection.outlook.com -all"
            """);

        var spf = Assert.Single(findings, f => f.Record == "SPF");

        Assert.Contains("\"v=spf1 include:spf.protection.outlook.com -all\"", spf.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInertSpfRecordThatDnsHasSinceBeenFixedIsNotStillAnEmergency()
    {
        // The zone file is a snapshot. Telling somebody to publish a fix they
        // published this morning is how a tool stops being read.
        var findings = Assess(
            """
            @	3600	IN	TXT	"include:spf.protection.outlook.com -all"
            """,
            Live(new PublishedRecords
            {
                Domain = "example.com",
                SpfRecords = ["v=spf1 include:spf.protection.outlook.com -all"],
                ApexTxt = ["v=spf1 include:spf.protection.outlook.com -all"],
            }));

        var spf = Assert.Single(findings, f => f.Record == "SPF" && f.Line > 0);

        Assert.Equal(HygieneSeverity.Tidy, spf.Severity);
        Assert.Equal(FindingSource.ZoneAndDns, spf.Source);
        Assert.Contains("older than the fix", spf.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInertSpfRecordLiveDnsStillCarriesIsSaidToBeConfirmed()
    {
        var findings = Assess(
            """
            @	3600	IN	TXT	"include:spf.protection.outlook.com -all"
            """,
            Live(new PublishedRecords
            {
                Domain = "example.com",
                ApexTxt = ["include:spf.protection.outlook.com -all"],
            }));

        var spf = Assert.Single(findings, f => f.Record == "SPF");

        Assert.Equal(HygieneSeverity.Breaking, spf.Severity);
        Assert.Equal(FindingSource.ZoneAndDns, spf.Source);
        Assert.Contains("Live DNS agrees", spf.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AVerificationTokenIsNotMistakenForABrokenSpfRecord()
    {
        // Every apex has half a dozen of these and none of them is SPF. A
        // wrong answer here has somebody prefixing v=spf1 onto a Microsoft
        // verification record, breaking that and publishing a second SPF
        // record in the same edit.
        var findings = Assess("""
            @	3600	IN	TXT	"MS=ms44548678"
            @	3600	IN	TXT	"pax8-verification=12a0dbf9-972b-3bf6-8669-c0fdeb76c07d"
            @	3600	IN	TXT	"google-site-verification=abcdefghijklmnop"
            @	3600	IN	TXT	"v=spf1 include:spf.protection.outlook.com -all"
            """);

        Assert.DoesNotContain(findings, f => f.Record == "SPF");
    }

    [Fact]
    public void ARecordDeclaringSomeOtherVersionIsLeftAlone()
    {
        var findings = Assess("""
            @	3600	IN	TXT	"v=STSv1; id=20260416"
            @	3600	IN	TXT	"v=spf1 -all"
            """);

        Assert.DoesNotContain(findings, f => f.Record == "SPF");
    }

    [Fact]
    public void TwoSpfRecordsAtTheApexAreBreakingBecauseSpfThenFailsForEverybody()
    {
        var findings = Assess("""
            @	3600	IN	TXT	"v=spf1 include:one.example -all"
            @	3600	IN	TXT	"v=spf1 include:two.example -all"
            """);

        var spf = Assert.Single(findings, f => f.Record == "SPF");

        Assert.Equal(HygieneSeverity.Breaking, spf.Severity);
    }

    // ---- DKIM ------------------------------------------------------------------

    [Fact]
    public void SelectorsAreEnumeratedFromTheZoneWhateverRecordTypeTheyUse()
    {
        // The whole reason a zone file is worth reading: DNS cannot be asked
        // which selectors a domain has, and which record type a provider uses
        // says nothing about whether the key works.
        var zone = Zone("""
            k1._domainkey	3600	IN	TXT	"v=DKIM1; p=AAAA"
            selector1._domainkey	3600	IN	CNAME	s1.example.onmicrosoft.com.
            abc.def._domainkey	3600	IN	CNAME	abc.def.dkim.amazonses.com.
            www	3600	IN	CNAME	@
            """);

        Assert.Equal(["abc.def", "k1", "selector1"], ZoneAudit.SelectorsIn(zone));
    }

    [Fact]
    public void TwoTxtRecordsAtOneSelectorIsAFindingBecauseNothingSaysWhichOneWins()
    {
        var findings = Assess($"""
            cm._domainkey	3600	IN	TXT	"{Key1024}"
            cm._domainkey	3600	IN	TXT	"v=DKIM1; p=AAAA"
            """);

        var duplicate = Assert.Single(findings, f => f.Problem.Contains("2 TXT records", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Weakness, duplicate.Severity);
        Assert.Equal(3, duplicate.Line);
    }

    [Fact]
    public void AKeyPublishedAsDkimRatherThanDkim1IsNotAKeyAtAll()
    {
        var findings = Assess("""
            cm._domainkey	3600	IN	TXT	"v=DKIM;k=rsa; p=AAAA"
            """);

        var broken = Assert.Single(findings, f => f.Problem.Contains("v=DKIM)", StringComparison.Ordinal));

        Assert.Contains("v=DKIM1", broken.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void ASelectorInTheZoneThatResolvesToNothingIsAFinding()
    {
        // The stale CNAME: a provider was removed, its selector record was
        // left behind, and the name it points at stopped existing.
        var findings = Assess(
            "abc._domainkey\t3600\tIN\tCNAME\tabc.dkim.amazonses.com.\n",
            Live(selectors: new() { ["abc"] = Resolved("abc", null) }));

        var dead = Assert.Single(findings, f => f.Record == "DKIM");

        Assert.Equal(HygieneSeverity.Tidy, dead.Severity);
        Assert.Equal(FindingSource.ZoneAndDns, dead.Source);
        Assert.Contains("abc.dkim.amazonses.com", dead.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ASelectorThatResolvesToNothingAndIsStillSigningMailIsBreaking()
    {
        var findings = Assess(
            "abc._domainkey\t3600\tIN\tCNAME\tabc.dkim.amazonses.com.\n",
            Live(selectors: new() { ["abc"] = Resolved("abc", null, seenSigning: true) }));

        var dead = Assert.Single(findings, f => f.Record == "DKIM");

        Assert.Equal(HygieneSeverity.Breaking, dead.Severity);
        Assert.Contains("before removing anything", dead.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void TheEmptyHalfOfAProvidersSelectorPairIsNotOfferedUpForDeletion()
    {
        // Microsoft publishes selector1 and selector2 for every domain and
        // serves a key at one of them until the first rotation. Removing the
        // empty one is what breaks DKIM months later, and nobody connects the
        // two events.
        var findings = Assess(
            """
            selector1._domainkey	3600	IN	CNAME	selector1-example-com._domainkey.example.onmicrosoft.com.
            selector2._domainkey	3600	IN	CNAME	selector2-example-com._domainkey.example.onmicrosoft.com.
            """,
            Live(selectors: new()
            {
                ["selector1"] = Resolved("selector1", Key2048),
                ["selector2"] = Resolved("selector2", null),
            }));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("selector2", StringComparison.Ordinal));
    }

    [Fact]
    public void AProviderWhoseSelectorsAllResolveToNothingIsStillReported()
    {
        // The other side of the same rule. Three Amazon SES selectors and no
        // key at any of them is a service configured in DNS and signing
        // nothing, which is worth knowing.
        var findings = Assess(
            """
            aaa._domainkey	3600	IN	CNAME	aaa.dkim.amazonses.com.
            bbb._domainkey	3600	IN	CNAME	bbb.dkim.amazonses.com.
            """,
            Live(selectors: new()
            {
                ["aaa"] = Resolved("aaa", null),
                ["bbb"] = Resolved("bbb", null),
            }));

        Assert.Equal(2, findings.Count(f => f.Record == "DKIM"));
    }

    [Fact]
    public void KeysUnder1024BitsAreBreakingRatherThanUntidy()
    {
        var findings = Assess(
            "small._domainkey\t3600\tIN\tCNAME\tsmall.dkim.provider.example.\n",
            Live(selectors: new() { ["small"] = Resolved("small", Key512) }));

        var size = Assert.Single(findings, f => f.Problem.Contains("under 1024 bits", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Breaking, size.Severity);
        Assert.Contains("small (512-bit)", size.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryThousandTwentyFourBitKeyIsOneFindingRatherThanOnePerSelector()
    {
        // Eleven of sixteen real domains were on 1024. One sentence about the
        // domain is a piece of work; eleven sentences is a wall nobody reads.
        var findings = Assess(
            """
            one._domainkey	3600	IN	CNAME	one.dkim.provider.example.
            two._domainkey	3600	IN	CNAME	two.dkim.provider.example.
            """,
            Live(selectors: new()
            {
                ["one"] = Resolved("one", Key1024),
                ["two"] = Resolved("two", Key1024),
            }));

        var size = Assert.Single(findings, f => f.Problem.Contains("1024-bit", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Weakness, size.Severity);
        Assert.Contains("one (1024-bit) and two (1024-bit)", size.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A2048BitKeyProducesNoFindingAtAll()
    {
        var findings = Assess(
            "good._domainkey\t3600\tIN\tCNAME\tgood.dkim.provider.example.\n",
            Live(selectors: new() { ["good"] = Resolved("good", Key2048) }));

        Assert.DoesNotContain(findings, f => f.Record == "DKIM");
    }

    [Fact]
    public void ASelectorThatHasNotSignedIsNotJudgedOnAFortnightOfReports()
    {
        // A staged key, a provider that publishes two and uses one, a service
        // that sends at quarter end. Silence over a fortnight is what all
        // three look like.
        var findings = Assess(
            "idle._domainkey\t3600\tIN\tCNAME\tidle.dkim.provider.example.\n",
            Live(selectors: new() { ["idle"] = Resolved("idle", Key2048) }, windowDays: 14));

        Assert.DoesNotContain(findings, f => f.Problem.Contains("no mail has been seen", StringComparison.Ordinal));
    }

    [Fact]
    public void ASelectorThatHasNotSignedInAFullWindowIsEvidenceRatherThanAnInstruction()
    {
        var findings = Assess(
            "idle._domainkey\t3600\tIN\tCNAME\tidle.dkim.provider.example.\n",
            Live(selectors: new() { ["idle"] = Resolved("idle", Key2048) }, windowDays: 45));

        var idle = Assert.Single(findings, f => f.Problem.Contains("no mail has been seen", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Tidy, idle.Severity);
        Assert.Equal(FindingSource.ZoneAndReports, idle.Source);
        Assert.DoesNotContain("Remove", idle.Fix, StringComparison.Ordinal);
        Assert.DoesNotContain("Delete", idle.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void ASelectorTheReportsHaveSeenAndTheFileHasNotIsUsuallyAStaleExport()
    {
        var findings = Assess(
            "old._domainkey\t3600\tIN\tCNAME\told.dkim.provider.example.\n",
            Live(selectors: new() { ["old"] = Resolved("old", Key2048, seenSigning: true) },
                 signing: ["old", "brandnew"], windowDays: 45));

        var missing = Assert.Single(findings, f => f.Problem.Contains("brandnew", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Tidy, missing.Severity);
        Assert.Contains("older than the record", missing.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void NothingIsSaidAboutAnySelectorWhenTheResolverDidNotAnswer()
    {
        // A lookup that failed is not an absent key. Every finding below
        // depends on a live answer, so there must be none.
        var findings = Assess(
            "abc._domainkey\t3600\tIN\tCNAME\tabc.dkim.amazonses.com.\n",
            Live(selectors: new()
            {
                ["abc"] = new SelectorEvidence { Selector = "abc", LiveRecords = null, LiveKey = null },
            }));

        Assert.DoesNotContain(findings, f => f.Record == "DKIM");
    }

    // ---- external reporting authorization ---------------------------------------

    [Fact]
    public void AReportAuthorizationSpelledInLowerCaseAuthorizesNothing()
    {
        // RFC 7489 writes the version out character by character, which in
        // ABNF is case sensitive. The receiver simply declines to send, and
        // what an operator sees is a customer that never generates reports.
        var findings = Assess("""
            other.example._report._dmarc	1800	IN	TXT	"v=dmarc1;"
            """);

        var broken = Assert.Single(findings, f => f.Record == "DMARC");

        Assert.Equal(HygieneSeverity.Breaking, broken.Severity);
        Assert.Contains("capitals", broken.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ACapitalVIsFineBecauseTagNamesAreNotCaseSensitive()
    {
        var findings = Assess("""
            other.example._report._dmarc	1800	IN	TXT	"V=DMARC1;"
            """);

        Assert.DoesNotContain(findings, f => f.Record == "DMARC");
    }

    [Theory]
    [InlineData("v=DMARC1")]
    [InlineData("v=DMARC1;")]
    [InlineData("v = DMARC1; rua=mailto:x@other.example")]
    public void AWellFormedReportAuthorizationIsLeftAlone(string record)
    {
        var findings = Assess($"other.example._report._dmarc\t1800\tIN\tTXT\t\"{record}\"\n");

        Assert.DoesNotContain(findings, f => f.Record == "DMARC");
    }

    [Fact]
    public void AReportAuthorizationForANameWithNoDotInItAuthorizesNoDomainThatExists()
    {
        // The shape a dropped suffix leaves behind, and invisible in a
        // provider's panel: the zone's own name is added on the end and the
        // whole row reads as a sensible hostname.
        var findings = Assess("""
            mcleanelectric._report._dmarc	3600	IN	TXT	"v=DMARC1;"
            """);

        var broken = Assert.Single(findings, f => f.Record == "DMARC");

        Assert.Equal(HygieneSeverity.Breaking, broken.Severity);
        Assert.Contains("mcleanelectric.com._report._dmarc", broken.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAuthorizationForADomainNobodyMonitorsIsWorthASecondLook()
    {
        // The transposed name. "ndgaa.com" beside "ndgga.com" reads correctly
        // in a column of near-identical rows, and the domain it was meant for
        // gets no reports at all while the record looks present.
        var evidence = Live(signing: [], windowDays: 45) with
        {
            Monitored = ["ndgga.com", "ndaco.org"],
        };

        var findings = Assess(
            """
            ndgaa.com._report._dmarc	1800	IN	TXT	"v=DMARC1;"
            ndaco.org._report._dmarc	1800	IN	TXT	"v=DMARC1;"
            """,
            evidence);

        var stray = Assert.Single(findings, f => f.Problem.Contains("ndgaa.com", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Tidy, stray.Severity);
        Assert.Equal(FindingSource.ZoneAndReports, stray.Source);
        Assert.DoesNotContain(findings, f => f.Problem.Contains("ndaco.org", StringComparison.Ordinal));
    }

    [Fact]
    public void NothingIsSaidAboutAuthorizationsWhenTheBookWasNotConsulted()
    {
        // With no database every authorization would otherwise be reported as
        // pointing at a stranger, which is the whole book flagged at once.
        var findings = Assess("""
            other.example._report._dmarc	1800	IN	TXT	"v=DMARC1;"
            """);

        Assert.DoesNotContain(findings, f => f.Problem.Contains("not a domain this install monitors", StringComparison.Ordinal));
    }

    // ---- delegation ---------------------------------------------------------------

    [Fact]
    public void NameServersAreNotJudgedUntilTheLiveDelegationHasBeenRead()
    {
        // A finding about name servers that was not checked against the
        // delegation is a guess, and acting on it moves a domain's DNS.
        var findings = Assess("""
            @	3600	IN	NS	ns01.domaincontrol.com.
            @	3600	IN	NS	courtney.ns.cloudflare.com.
            """);

        Assert.DoesNotContain(findings, f => f.Record == "NS");
    }

    [Fact]
    public void AProvidersLeftoverNameServersInsideAnotherProvidersZoneAreAFinding()
    {
        var findings = Assess(
            """
            @	86400	IN	NS	courtney.ns.cloudflare.com.
            @	86400	IN	NS	elmo.ns.cloudflare.com.
            @	1	IN	NS	ns01.domaincontrol.com.
            @	1	IN	NS	ns02.domaincontrol.com.
            """,
            Live(delegation: ["courtney.ns.cloudflare.com", "elmo.ns.cloudflare.com"]));

        var ns = Assert.Single(findings, f => f.Record == "NS");

        Assert.Equal(HygieneSeverity.Weakness, ns.Severity);
        Assert.Equal(FindingSource.ZoneAndDns, ns.Source);
        Assert.Contains("ns01.domaincontrol.com and ns02.domaincontrol.com", ns.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AZoneExportedFromAProviderThatServesNoneOfTheDelegationIsSaidSoLoudly()
    {
        // Everything else in the file would then be describing a zone nobody
        // is serving, which is worth knowing before reading any of it.
        var findings = Assess(
            "@\t3600\tIN\tNS\tns01.domaincontrol.com.\n",
            Live(delegation: ["courtney.ns.cloudflare.com"]));

        var ns = Assert.Single(findings, f => f.Record == "NS");

        Assert.Contains("None of them match", ns.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ADelegationThatMatchesTheZoneProducesNothing()
    {
        var findings = Assess(
            "@\t3600\tIN\tNS\tns51.domaincontrol.com.\n",
            Live(delegation: ["ns51.domaincontrol.com"]));

        Assert.DoesNotContain(findings, f => f.Record == "NS");
    }

    // ---- structure -----------------------------------------------------------------

    [Fact]
    public void ACnameSharingANameWithAnotherRecordHidesOneOfThem()
    {
        var findings = Assess("""
            mail	3600	IN	CNAME	target.example.
            mail	3600	IN	TXT	"something"
            """);

        var clash = Assert.Single(findings, f => f.Record == "zone");

        Assert.Equal(HygieneSeverity.Breaking, clash.Severity);
        Assert.Contains("mail.example.com", clash.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ACnameOnItsOwnIsFine()
    {
        var findings = Assess("mail\t3600\tIN\tCNAME\ttarget.example.\n");

        Assert.DoesNotContain(findings, f => f.Record == "zone");
    }

    // ---- the file against DNS ---------------------------------------------------------

    [Fact]
    public void AFileAndDnsHoldingDifferentDmarcRecordsIsStatedRatherThanPickedBetween()
    {
        var findings = Assess(
            "_dmarc\t1800\tIN\tTXT\t\"v=DMARC1; p=none\"\n",
            Live(new PublishedRecords
            {
                Domain = "example.com",
                DmarcRecord = "v=DMARC1; p=reject",
            }));

        var diff = Assert.Single(findings, f => f.Problem.Contains("different DMARC records", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Tidy, diff.Severity);
        Assert.Contains("p=none", diff.Problem, StringComparison.Ordinal);
        Assert.Contains("p=reject", diff.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void RecordsDifferingOnlyInSpacingAreTheSameRecord()
    {
        var findings = Assess(
            "_dmarc\t1800\tIN\tTXT\t\"v=DMARC1;  p=reject\"\n",
            Live(new PublishedRecords { Domain = "example.com", DmarcRecord = "v=DMARC1; p=reject" }));

        Assert.Empty(findings);
    }

    // ---- guards -----------------------------------------------------------------------

    [Fact]
    public void AFileWithNoOriginIsRefusedRatherThanJudgedAgainstAGuess()
    {
        var findings = ZoneAudit.Assess(ZoneFile.Parse("mail\t3600\tIN\tA\t192.0.2.1\n"), new ZoneEvidence());

        var problem = Assert.Single(findings);

        Assert.Contains("does not say which domain", problem.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AFileWithNoRecordsSaysSoRatherThanReportingACleanZone()
    {
        var findings = ZoneAudit.Assess(ZoneFile.Parse("$ORIGIN example.com.\n"), new ZoneEvidence());

        var problem = Assert.Single(findings);

        Assert.Contains("No records could be read", problem.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AZoneWithNothingWrongWithItProducesNothing()
    {
        var findings = Assess($"""
            @	3600	IN	TXT	"v=spf1 include:spf.protection.outlook.com -all"
            @	3600	IN	TXT	"MS=ms44548678"
            _dmarc	1800	IN	TXT	"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            other.example._report._dmarc	1800	IN	TXT	"v=DMARC1"
            sel._domainkey	3600	IN	TXT	"{Key2048}"
            www	3600	IN	CNAME	@
            @	3600	IN	MX	0	example-com.mail.protection.outlook.com.
            """);

        Assert.Empty(findings);
    }

    [Fact]
    public void FindingsComeBackWorstFirst()
    {
        var findings = Assess("""
            @	3600	IN	TXT	"include:one.example -all"
            mail	3600	IN	CNAME	target.example.
            mail	3600	IN	TXT	"something"
            other.example._report._dmarc	1800	IN	TXT	"v=dmarc1"
            """);

        Assert.NotEmpty(findings);
        Assert.Equal(
            findings.OrderByDescending(f => f.Severity).Select(f => f.Problem),
            findings.Select(f => f.Problem));
    }

    [Fact]
    public async Task AZoneForAnotherDomainIsRefusedBeforeAnythingIsLookedUp()
    {
        // The mis-paste, and the most convincing wrong answer this could give:
        // every name placed under a domain it has nothing to do with, matched
        // against a third party's reports, and reading as careful findings
        // about the customer on screen. Nothing is resolved, so this test does
        // not touch the network either.
        var report = await new ZoneAuditor().RunAsync(
            "$ORIGIN other.example.\nmail\t3600\tIN\tA\t192.0.2.1\n", "example.com");

        var wrong = Assert.Single(report.Findings);

        Assert.Equal(HygieneSeverity.Breaking, wrong.Severity);
        Assert.Contains("zone for other.example", wrong.Problem, StringComparison.Ordinal);
        Assert.Empty(report.Evidence.Selectors);
    }

    [Theory]
    [InlineData(FindingSource.Zone, "the file alone")]
    [InlineData(FindingSource.ZoneAndDns, "confirmed against live DNS")]
    [InlineData(FindingSource.Dns, "live DNS")]
    [InlineData(FindingSource.ZoneAndReports, "what the reports have seen")]
    public void EveryFindingCanSayWhereItCameFrom(FindingSource source, string expected)
    {
        Assert.Contains(expected, ZoneAudit.Describe(source), StringComparison.Ordinal);
    }
}
