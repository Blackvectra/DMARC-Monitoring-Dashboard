using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Reading a published DMARC record.
///
/// Used by the hygiene check and by the domain page, which is the point: both
/// read the same record, and two parsers would eventually disagree about what
/// a customer has published while each looked right on its own.
/// </summary>
public sealed class DmarcRecordTests
{
    [Fact]
    public void ReadsTheTagsThatDecideWhatHappensToMail()
    {
        // A real record, from a live domain.
        var r = DmarcRecord.Parse(
            "v=DMARC1; p=quarantine; pct=100; sp=none; adkim=r; aspf=r; fo=1; "
            + "rua=mailto:dmarc@nrgtechservices.com; ruf=mailto:dmarc@nrgtechservices.com");

        Assert.True(r.IsValid);
        Assert.Equal("quarantine", r.Policy);
        Assert.Equal("none", r.SubdomainPolicy);
        Assert.Equal(100, r.Percent);
        Assert.Equal("mailto:dmarc@nrgtechservices.com", r.Rua);
    }

    [Fact]
    public void AnAbsentSubdomainPolicyIsNotTheSameAsOneSetToMatch()
    {
        // Absent means subdomains follow the domain wherever it goes next.
        // Explicitly equal means somebody has to remember to change both, and
        // collapsing the two here would hide that from the page.
        var inherits = DmarcRecord.Parse("v=DMARC1; p=reject");
        var explicitly = DmarcRecord.Parse("v=DMARC1; p=reject; sp=reject");

        Assert.Equal("", inherits.SubdomainPolicy);
        Assert.Equal("reject", explicitly.SubdomainPolicy);

        // Both end up treating subdomains the same way today.
        Assert.Equal("reject", inherits.EffectiveSubdomainPolicy);
        Assert.Equal("reject", explicitly.EffectiveSubdomainPolicy);
    }

    [Fact]
    public void AWeakSubdomainPolicyIsReadAsItself()
    {
        // Two live domains publish this: the domain protected, everything
        // under it open.
        var r = DmarcRecord.Parse("v=DMARC1; p=quarantine; sp=none; rua=mailto:x@example.com");

        Assert.Equal("quarantine", r.Policy);
        Assert.Equal("none", r.EffectiveSubdomainPolicy);
    }

    [Fact]
    public void AMissingPercentMeansAllOfIt()
    {
        Assert.Equal(100, DmarcRecord.Parse("v=DMARC1; p=reject").Percent);
    }

    [Theory]
    [InlineData("v=DMARC1; p=reject; pct=20", 20)]
    [InlineData("v=DMARC1; p=reject; pct=0", 0)]
    [InlineData("v=DMARC1; p=reject; pct=notanumber", 100)]
    public void ReadsThePercentOrFallsBackToAll(string record, int expected)
    {
        // An unreadable pct falls back to 100 rather than 0. Zero would report
        // a domain as enforcing nothing, which is a claim; 100 matches what a
        // receiver does with a record it cannot parse the tag of.
        Assert.Equal(expected, DmarcRecord.Parse(record).Percent);
    }

    [Fact]
    public void NoRuaMeansNobodyIsWatching()
    {
        Assert.Equal("", DmarcRecord.Parse("v=DMARC1; p=reject").Rua);
    }

    [Theory]
    [InlineData("V=DMARC1; P=REJECT")]
    [InlineData("v=DMARC1;p=reject")]
    [InlineData("  v=DMARC1 ; p = reject ; ")]
    public void ToleratesTheSpacingAndCaseRealRecordsArriveWith(string record)
    {
        // Hand-edited in a provider control panel. Refusing these would report
        // a working record as absent.
        var r = DmarcRecord.Parse(record);

        Assert.True(r.IsValid);
        Assert.Equal("reject", r.Policy.ToLowerInvariant());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("v=spf1 -all")]
    [InlineData("google-site-verification=abc")]
    [InlineData("p=reject")]
    public void RefusesAnythingThatIsNotADmarcRecord(string text)
    {
        // Other TXT records live at _dmarc on plenty of domains. Treating one
        // as a broken DMARC record would have somebody edit the wrong thing.
        var r = DmarcRecord.Parse(text);

        Assert.False(r.IsValid);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public void KeepsTheRecordAsPublishedForShowingBack()
    {
        // The page prints this verbatim so an operator can recognize their own
        // record rather than a reconstruction of it.
        const string raw = "v=DMARC1; p=reject; rua=mailto:x@example.com";

        Assert.Equal(raw, DmarcRecord.Parse(raw).Raw);
    }

    [Theory]
    [InlineData("v=DMARC1; p=reject; adkim=s; aspf=s", true, true)]
    [InlineData("v=DMARC1; p=reject; adkim=S; aspf=S", true, true)]
    [InlineData("v=DMARC1; p=reject; adkim=s", true, false)]
    [InlineData("v=DMARC1; p=reject; aspf=s", false, true)]
    [InlineData("v=DMARC1; p=reject; adkim=r; aspf=r", false, false)]
    public void ReadsStrictAlignment(string raw, bool dkim, bool spf)
    {
        // The tag that quietly refuses a domain's own correctly-signed mail
        // from a subdomain. Nothing read it before, so the page could not say
        // why an otherwise valid signature was not counting.
        var r = DmarcRecord.Parse(raw);

        Assert.Equal(dkim, r.StrictDkim);
        Assert.Equal(spf, r.StrictSpf);
    }

    [Fact]
    public void AlignmentIsRelaxedWhenTheRecordDoesNotSay()
    {
        // RFC 7489's default, and most records omit the tags. Defaulting to
        // strict would describe the majority of domains as rejecting subdomain
        // signatures they actually accept.
        var r = DmarcRecord.Parse("v=DMARC1; p=reject; rua=mailto:x@example.com");

        Assert.False(r.StrictDkim);
        Assert.False(r.StrictSpf);
    }
}
