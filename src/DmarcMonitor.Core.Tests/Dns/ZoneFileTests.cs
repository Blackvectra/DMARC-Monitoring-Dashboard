using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Reading the two zone-file dialects operators actually paste.
///
/// The fixtures here are built to the shape of five real exports - three from
/// GoDaddy, one from Cloudflare, one hand-edited - with the domains and the
/// key material replaced. The shapes are what matter and they are all
/// awkward: relative names against absolute ones, an origin that is only in a
/// comment, a TXT record split across two strings mid-base64, a record whose
/// owner name is the single character "@" in the middle of a longer name.
///
/// Every one of these was a real defect in the first draft of the parser.
/// </summary>
public sealed class ZoneFileTests
{
    /// <summary>A GoDaddy export: $ORIGIN, relative names, tabs, a bracketed SOA.</summary>
    private const string GoDaddy = """
        ; Domain: example.com
        ; Exported (y-m-d hh:mm:ss): 2026-09-21 10:33:17
        ;
        ; Use at your own risk.


        $ORIGIN example.com.

        ; SOA Record
        @	3600	 IN 	SOA	ns51.domaincontrol.com.	dns.jomax.net. (
        					2026091600
        					28800
        					7200
        					604800
        					3600
        					)

        ; A Record
        @	3600	 IN 	A	192.0.2.1
        vpn	3600	 IN 	A	192.0.2.9

        ; TXT Record
        @	3600	 IN 	TXT	"v=spf1 include:spf.protection.outlook.com -all"
        @	3600	 IN 	TXT	"pax8-verification=12a0dbf9-972b"
        _dmarc	1800	 IN 	TXT	"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        sel._domainkey	1800	 IN 	TXT	"v=DKIM1; k=rsa; p=AAAA"	"BBBB"

        ; CNAME Record
        www	3600	 IN 	CNAME	@
        selector1._domainkey	3600	 IN 	CNAME	selector1-example-com._domainkey.example.onmicrosoft.com.

        ; SRV Record
        _sip._tls.@	3600	 IN 	SRV	100	1	443	sipdir.online.lync.com.

        ; NS Record
        @	3600	 IN 	NS	ns51.domaincontrol.com.

        ; MX Record
        @	3600	 IN 	MX	0	example-com.mail.protection.outlook.com.
        """;

    /// <summary>A Cloudflare export: absolute names, no $ORIGIN, trailing cf_tags comments.</summary>
    private const string Cloudflare = """
        ;;
        ;; Domain:     example.dev.
        ;; Exported:   2026-09-21 17:40:08
        ;;
        ;; Use at your own risk.
        ;; SOA Record
        example.dev	3600	IN	SOA	courtney.ns.cloudflare.com. dns.cloudflare.com. 2054167900 10000 2400 604800 3600

        ;; NS Records
        example.dev.	86400	IN	NS	courtney.ns.cloudflare.com.
        example.dev.	86400	IN	NS	elmo.ns.cloudflare.com.

        ;; CNAME Records
        www.example.dev.	1	IN	CNAME	example.dev. ; cf_tags=cf-proxied:true
        selector1._domainkey.example.dev.	3600	IN	CNAME	s1._domainkey.example.n-v1.dkim.mail.microsoft. ; cf_tags=cf-proxied:false

        ;; TXT Records
        example.dev.	3600	IN	TXT	"v=spf1 include:spf.protection.outlook.com -all"
        _dmarc.example.dev.	1	IN	TXT	"v=DMARC1; p=reject; rua=mailto:support@example.dev"
        """;

    [Fact]
    public void TheOriginComesFromTheDirectiveWhenThereIsOne()
    {
        Assert.Equal("example.com", ZoneFile.Parse(GoDaddy).Origin);
    }

    [Fact]
    public void TheOriginComesFromTheHeaderCommentWhenThereIsNoDirective()
    {
        // Cloudflare exports carry no $ORIGIN at all. Without this the file
        // parses into a zone for nothing and every name in it is unplaceable.
        Assert.Equal("example.dev", ZoneFile.Parse(Cloudflare).Origin);
    }

    [Fact]
    public void TheOriginComesFromTheSoaWhenTheHeaderHasBeenTrimmedOff()
    {
        var body = string.Join('\n', Cloudflare.Split('\n').Where(l => !l.StartsWith(";;", StringComparison.Ordinal)));

        Assert.Equal("example.dev", ZoneFile.Parse(body).Origin);
    }

    [Fact]
    public void ACallerCanNameTheDomainWhenTheFileDoesNot()
    {
        var body = string.Join('\n', Cloudflare.Split('\n')
            .Where(l => !l.StartsWith(";;", StringComparison.Ordinal) && !l.Contains("SOA", StringComparison.Ordinal)));

        Assert.Equal("example.dev", ZoneFile.Parse(body, "example.dev.").Origin);
    }

    [Fact]
    public void TheFileWinsAboutWhichZoneItIsAndSaysSoSeparately()
    {
        // The mis-paste. Taking the caller's word would place every name in
        // the file under a domain it has nothing to do with, and every finding
        // that followed would read as a fact about the wrong customer.
        var zone = ZoneFile.Parse(GoDaddy, "other.example.");

        Assert.Equal("example.com", zone.Origin);
        Assert.Equal("example.com", zone.DeclaredOrigin);
    }

    [Fact]
    public void AFileThatNamesNoDomainDeclaresNone()
    {
        var zone = ZoneFile.Parse("mail\t3600\tIN\tA\t192.0.2.1\n", "example.com");

        Assert.Equal("example.com", zone.Origin);
        Assert.Equal("", zone.DeclaredOrigin);
    }

    [Fact]
    public void AtSignMeansTheApex()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Contains(zone.Records, r => r.Type == "A" && r.Name == "example.com");
    }

    [Fact]
    public void ARelativeNameIsPlacedUnderTheOrigin()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Contains(zone.Records, r => r.Type == "A" && r.Name == "vpn.example.com");
    }

    [Fact]
    public void AnAbsoluteNameIsLeftAlone()
    {
        var zone = ZoneFile.Parse(Cloudflare);

        Assert.Contains(zone.Records, r => r.Type == "CNAME" && r.Name == "www.example.dev");
    }

    [Fact]
    public void TheApexWrittenWithoutATrailingDotIsStillTheApex()
    {
        // Cloudflare writes every name in full except the SOA's, which has no
        // trailing dot. Treated as relative it becomes example.dev.example.dev.
        var zone = ZoneFile.Parse(Cloudflare);

        Assert.Contains(zone.Records, r => r.Type == "SOA" && r.Name == "example.dev");
        Assert.DoesNotContain(zone.Records, r => r.Name.Contains("example.dev.example.dev", StringComparison.Ordinal));
    }

    [Fact]
    public void ANameThatAlreadyEndsInTheDomainIsStillPlacedUnderItInARelativeFile()
    {
        // The classic control-panel slip: "mail.example.com" typed into a
        // field that appends the domain. The file means what it says, and a
        // parser that quietly repairs it hides the defect somebody is running
        // this to find.
        var zone = ZoneFile.Parse("$ORIGIN example.com.\nmail.example.com\t3600\tIN\tA\t192.0.2.5\n");

        Assert.Contains(zone.Records, r => r.Name == "mail.example.com.example.com");
    }

    [Fact]
    public void GoDaddysAtSignInTheMiddleOfANameIsReadAsTheOrigin()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Contains(zone.Records, r => r.Type == "SRV" && r.Name == "_sip._tls.example.com");
    }

    [Fact]
    public void ABracketedRecordIsOneRecordRatherThanSix()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Single(zone.Records, r => r.Type == "SOA");
        Assert.Empty(zone.Problems);
    }

    [Fact]
    public void ATxtRecordSplitAcrossTwoStringsIsJoinedWithNothingBetween()
    {
        // DNS splits anything over 255 characters, and every DKIM key of any
        // size arrives this way. A space between the halves corrupts the
        // base64 and produces a confident finding about a key that is fine.
        var zone = ZoneFile.Parse(GoDaddy);

        var key = zone.At("sel._domainkey.example.com", "TXT").Single();

        Assert.Equal("v=DKIM1; k=rsa; p=AAAABBBB", key.Value);
    }

    [Fact]
    public void ASemicolonInsideAQuotedStringIsNotAComment()
    {
        // Every DMARC and DKIM record is full of them.
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Equal(
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            zone.At("_dmarc.example.com", "TXT").Single().Value);
    }

    [Fact]
    public void ATrailingCommentIsDropped()
    {
        var zone = ZoneFile.Parse(Cloudflare);

        Assert.Equal("example.dev", zone.At("www.example.dev", "CNAME").Single().Target);
    }

    [Fact]
    public void ACnameTargetIsQualified()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Equal(
            "selector1-example-com._domainkey.example.onmicrosoft.com",
            zone.At("selector1._domainkey.example.com", "CNAME").Single().Target);
    }

    [Fact]
    public void AnMxTargetIsTheHostRatherThanThePreference()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Equal(
            "example-com.mail.protection.outlook.com",
            zone.At("example.com", "MX").Single().Target);
    }

    [Fact]
    public void ASrvTargetIsTheHostRatherThanThePort()
    {
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Equal("sipdir.online.lync.com", zone.At("_sip._tls.example.com", "SRV").Single().Target);
    }

    [Fact]
    public void ARecordWithNoOwnerNameBelongsToTheOneAboveIt()
    {
        var zone = ZoneFile.Parse("""
            $ORIGIN example.com.
            mail	3600	IN	A	192.0.2.1
            	3600	IN	TXT	"second"
            """);

        Assert.Equal(2, zone.Records.Count);
        Assert.All(zone.Records, r => Assert.Equal("mail.example.com", r.Name));
    }

    [Fact]
    public void AZonePastedWithEveryLineIndentedIsStillRead()
    {
        // The paste box exists so somebody can paste from anywhere, and text
        // copied out of a document, a ticket or a chat arrives uniformly
        // indented. In BIND a leading space means "same owner as the line
        // before", so read literally every line inherits from nothing and the
        // whole file produces no records at all - which reads as the tool
        // being broken rather than as the paste being indented.
        //
        // Where no line is flush, the indentation cannot be carrying the
        // meaning BIND gives it, because there is no line for the first one to
        // inherit from. So it is a paste artifact and is ignored.
        var zone = ZoneFile.Parse("""
                $ORIGIN example.com.
                @	3600	IN	TXT	"v=spf1 -all"
                _dmarc	1800	IN	TXT	"v=DMARC1; p=reject"
                www	3600	IN	CNAME	@
            """);

        Assert.Equal(3, zone.Records.Count);
        Assert.Empty(zone.Problems);
        Assert.Equal("example.com", zone.Origin);
    }

    [Fact]
    public void AnIndentedContinuationStillMeansWhatBindSaysItMeans()
    {
        // The other half: where SOME lines are flush, indentation is doing its
        // real job and must not be thrown away. A multi-line SOA and an
        // owner-less record both depend on it.
        var zone = ZoneFile.Parse("""
            $ORIGIN example.com.
            mail	3600	IN	A	192.0.2.1
            	3600	IN	TXT	"second record, same owner"
            """);

        Assert.Equal(2, zone.Records.Count);
        Assert.All(zone.Records, r => Assert.Equal("mail.example.com", r.Name));
    }

    [Fact]
    public void ARecordWithNoOwnerNameAndNothingAboveItIsReportedRatherThanGuessedAt()
    {
        var zone = ZoneFile.Parse("$ORIGIN example.com.\n\t3600\tIN\tA\t192.0.2.1\n");

        Assert.Empty(zone.Records);
        Assert.Single(zone.Problems);
    }

    [Theory]
    [InlineData("3600", 3600)]
    [InlineData("1h", 3600)]
    [InlineData("1h30m", 5400)]
    [InlineData("1w", 604800)]
    public void TtlsAreReadWithOrWithoutUnits(string written, int seconds)
    {
        Assert.Equal(seconds, ZoneFile.Ttl(written));
    }

    [Theory]
    [InlineData("IN")]
    [InlineData("A")]
    [InlineData("TXT")]
    [InlineData("3600x")]
    [InlineData("1h30")]
    public void AClassOrATypeIsNeverMistakenForATtl(string token)
    {
        // Reading one as a TTL consumes the record's type and leaves the whole
        // line unparseable, which is how a zone quietly reads as half a zone.
        Assert.Null(ZoneFile.Ttl(token));
    }

    [Fact]
    public void ATtlDirectiveAppliesToRecordsThatOmitOne()
    {
        var zone = ZoneFile.Parse("$ORIGIN example.com.\n$TTL 900\nmail\tIN\tA\t192.0.2.1\n");

        Assert.Equal(900, zone.Records.Single().Ttl);
    }

    [Fact]
    public void ARecordWithNeitherTtlNorClassIsStillRead()
    {
        var zone = ZoneFile.Parse("$ORIGIN example.com.\nmail\tA\t192.0.2.1\n");

        Assert.Equal("A", zone.Records.Single().Type);
    }

    [Fact]
    public void AnUnclosedQuoteIsReportedRatherThanSwallowingTheRestOfTheFile()
    {
        var zone = ZoneFile.Parse("""
            $ORIGIN example.com.
            broken	3600	IN	TXT	"never closed
            mail	3600	IN	A	192.0.2.1
            """);

        Assert.Single(zone.Problems);
        Assert.Contains(zone.Records, r => r.Name == "mail.example.com");
    }

    [Fact]
    public void AnIncludeDirectiveIsReportedBecauseItMeansTheFileIsNotTheWholeZone()
    {
        // A zone audited as though it were complete, when a whole file of it
        // was never read, is an all-clear about records nobody looked at.
        var zone = ZoneFile.Parse("$ORIGIN example.com.\n$INCLUDE sub.zone\n");

        Assert.Single(zone.Problems);
        Assert.Contains("$INCLUDE", zone.Problems[0].Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ALineNumberIsKeptSoAFindingCanSayWhereToLook()
    {
        var zone = ZoneFile.Parse("$ORIGIN example.com.\nmail\t3600\tIN\tA\t192.0.2.1\n");

        Assert.Equal(2, zone.Records.Single().Line);
    }

    [Fact]
    public void AnEmptyFileParsesIntoNothingRatherThanThrowing()
    {
        var zone = ZoneFile.Parse("");

        Assert.Empty(zone.Records);
        Assert.Empty(zone.Problems);
        Assert.Equal("", zone.Origin);
    }

    [Fact]
    public void CarriageReturnsDoNotEndUpInsideRecords()
    {
        var zone = ZoneFile.Parse("$ORIGIN example.com.\r\nmail\t3600\tIN\tTXT\t\"value\"\r\n");

        Assert.Equal("value", zone.Records.Single().Value);
    }

    [Fact]
    public void EveryRecordInARealSizedExportIsAccountedFor()
    {
        // The count is the cheapest guard against a dialect quirk dropping a
        // whole block: 1 SOA, 2 A, 4 TXT, 2 CNAME, 1 SRV, 1 NS, 1 MX.
        var zone = ZoneFile.Parse(GoDaddy);

        Assert.Equal(12, zone.Records.Count);
        Assert.Empty(zone.Problems);
    }
}
