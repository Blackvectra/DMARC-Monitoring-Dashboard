using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Reading an SPF record.
///
/// The lookup count is the reason this exists, and it is a cliff rather than a
/// budget: one over the limit and SPF returns an error, which is not a pass,
/// so mail that should authenticate stops. Counting the wrong terms in either
/// direction is the difference between telling somebody their record is fine
/// and telling them it is about to break.
/// </summary>
public sealed class SpfRecordTests
{
    [Fact]
    public void ReadsARecordAsWritten()
    {
        var r = SpfRecord.Parse("v=spf1 include:spf.protection.outlook.com ip4:192.0.2.1 -all");

        Assert.True(r.IsValid);
        Assert.Equal(3, r.Terms.Count);
        Assert.Equal("include", r.Terms[0].Name);
        Assert.Equal("spf.protection.outlook.com", r.Terms[0].Value);
        Assert.Equal("ip4", r.Terms[1].Name);
        Assert.Equal("all", r.Terms[2].Name);
        Assert.Equal('-', r.Terms[2].Qualifier);
    }

    [Theory]
    [InlineData("include:x.example", true)]
    [InlineData("a", true)]
    [InlineData("a:mail.example", true)]
    [InlineData("mx", true)]
    [InlineData("ptr", true)]
    [InlineData("exists:%{i}.example", true)]
    [InlineData("redirect=other.example", true)]
    [InlineData("ip4:192.0.2.0/24", false)]
    [InlineData("ip6:2001:db8::/32", false)]
    [InlineData("all", false)]
    public void KnowsWhichTermsCostADnsLookup(string term, bool costs)
    {
        // RFC 7208 §4.6.4 names exactly these. ip4 and ip6 being free is the
        // whole reason replacing an include with its addresses works.
        var r = SpfRecord.Parse($"v=spf1 {term} -all");

        Assert.Equal(costs, r.Terms[0].CostsALookup);
    }

    [Fact]
    public void CountsOnlyTheTermsInThisRecord()
    {
        // Named Direct because it is a floor: each include spends more once
        // followed, and the limit applies to the whole evaluation.
        var r = SpfRecord.Parse("v=spf1 mx a include:one.example include:two.example ip4:192.0.2.1 -all");

        Assert.Equal(4, r.DirectLookups);
    }

    [Theory]
    [InlineData("v=spf1 -all", '-')]
    [InlineData("v=spf1 ~all", '~')]
    [InlineData("v=spf1 ?all", '?')]
    [InlineData("v=spf1 +all", '+')]
    [InlineData("v=spf1 all", '+')]
    public void ReadsTheQualifierOnAllIncludingWhenItIsImplicit(string record, char expected)
    {
        // A bare "all" means "+all", which authorizes the internet. Defaulting
        // it to anything else would hide the worst record there is.
        Assert.Equal(expected, SpfRecord.Parse(record).All!.Qualifier);
    }

    [Fact]
    public void TakesTheLastAllWhenSomebodyLeftTwo()
    {
        // Only the first is evaluated in practice, but a record with two is
        // already confused; reading the last matches what an operator sees at
        // the end of the line they are editing.
        var r = SpfRecord.Parse("v=spf1 ~all include:x.example -all");

        Assert.Equal('-', r.All!.Qualifier);
    }

    [Fact]
    public void HasNoAllWhenTheRecordOmitsIt()
    {
        Assert.Null(SpfRecord.Parse("v=spf1 include:x.example").All);
    }

    // ---- what real records look like -----------------------------------------

    [Theory]
    [InlineData("V=SPF1 -ALL")]
    [InlineData("v=spf1   include:x.example    -all")]
    [InlineData("  v=spf1 -all  ")]
    public void ToleratesCaseAndSpacingBecauseControlPanelsProduceThem(string record)
    {
        // These are hand-edited in provider control panels and arrive with
        // capitals and double spaces. Refusing them would report a working
        // record as broken.
        Assert.True(SpfRecord.Parse(record).IsValid);
    }

    [Fact]
    public void ReadsAModifierWithoutTreatingItsNameAsAQualifier()
    {
        var r = SpfRecord.Parse("v=spf1 redirect=other.example");

        Assert.Equal("redirect", r.Terms[0].Name);
        Assert.Equal("other.example", r.Terms[0].Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("google-site-verification=abc123")]
    [InlineData("v=DMARC1; p=reject")]
    [InlineData("spf1 -all")]
    public void RefusesAnythingThatIsNotAnSpfRecord(string text)
    {
        // An apex holds verification tokens for half a dozen services. Treating
        // one as a broken SPF record would have somebody edit the wrong thing.
        var r = SpfRecord.Parse(text);

        Assert.False(r.IsValid);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public void KeepsEachTermAsItWasWrittenForShowingBack()
    {
        // An operator reading a finding needs to recognize their own record.
        var r = SpfRecord.Parse("v=spf1 ~include:MixedCase.Example -all");

        Assert.Equal("~include:MixedCase.Example", r.Terms[0].Raw);
        Assert.Equal("include", r.Terms[0].Name);
    }
}
