using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// Per-domain report addresses and the attribution they make possible.
///
/// The security property being tested is narrow and worth stating: a
/// published rua address is public, so anyone can send mail to it. Without a
/// per-domain address, a report is attributed by reading the domain out of
/// the XML, which the sender controls. That means fabricated reports can be
/// filed against any monitored domain by anyone who can send an email.
///
/// These tests exist to make sure the address and the report have to AGREE,
/// and that disagreement is surfaced rather than resolved in favour of
/// whichever is more convenient.
/// </summary>
public sealed class ReportAddressTests
{
    private const string ReportingDomain = "rua.nrgsecure.com";

    // ---- token generation ---------------------------------------------------

    [Fact]
    public void GeneratesATokenOfTheExpectedShape()
    {
        var token = ReportAddress.GenerateToken();
        Assert.Equal(ReportAddress.TokenLength, token.Length);
        Assert.True(ReportAddress.IsValidToken(token));
    }

    [Fact]
    public void NeverGeneratesTheSameTokenTwice()
    {
        var tokens = Enumerable.Range(0, 5000).Select(_ => ReportAddress.GenerateToken()).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(5000, tokens.Count);
    }

    [Fact]
    public void ExcludesCharactersThatAreMisreadWhenTypedByHand()
    {
        // These get read down a phone and copied into a customer's DNS.
        // i/l/1 and o/0 confusion turns into a domain that receives nothing.
        var all = string.Concat(Enumerable.Range(0, 400).Select(_ => ReportAddress.GenerateToken()));
        Assert.DoesNotContain('i', all);
        Assert.DoesNotContain('l', all);
        Assert.DoesNotContain('o', all);
        Assert.DoesNotContain('u', all);
    }

    [Fact]
    public void UsesTheWholeAlphabet()
    {
        // A masking bug that collapsed the range would quietly shrink the
        // keyspace while still producing valid-looking tokens.
        var seen = new HashSet<char>(string.Concat(Enumerable.Range(0, 2000).Select(_ => ReportAddress.GenerateToken())));
        Assert.Equal(32, seen.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("waytoolongtobeavalidtokenatall")]
    [InlineData("abcdefghijklmnop")]  // contains excluded letters
    [InlineData("ABCDEFGH12345678")]  // upper case
    [InlineData("abcd efgh 1234 56")]
    public void RejectsAMalformedToken(string? token)
    {
        Assert.False(ReportAddress.IsValidToken(token));
    }

    // ---- building -----------------------------------------------------------

    [Fact]
    public void BuildsThePublishableAddress()
    {
        var token = ReportAddress.GenerateToken();
        Assert.Equal($"{token}@rua.nrgsecure.com", ReportAddress.Build(token, ReportingDomain));
    }

    [Fact]
    public void NormalizesTheReportingDomainWhenBuilding()
    {
        var token = ReportAddress.GenerateToken();
        Assert.Equal($"{token}@rua.nrgsecure.com", ReportAddress.Build(token, "RUA.NRGSecure.com."));
    }

    [Fact]
    public void RefusesToBuildFromAnInvalidToken()
    {
        Assert.Throws<ArgumentException>(() => ReportAddress.Build("nope", ReportingDomain));
    }

    // ---- parsing what actually arrives ---------------------------------------

    [Fact]
    public void ParsesAPlainAddress()
    {
        var token = ReportAddress.GenerateToken();
        Assert.True(ReportAddress.TryParse($"{token}@rua.nrgsecure.com", ReportingDomain, out var parsed));
        Assert.Equal(token, parsed);
    }

    [Theory]
    [InlineData("DMARC Reports <{0}@rua.nrgsecure.com>")]
    [InlineData("  {0}@rua.nrgsecure.com  ")]
    [InlineData("{0}@RUA.NRGSECURE.COM")]
    [InlineData("<{0}@rua.nrgsecure.com>")]
    public void ParsesTheShapesReceiversActuallySend(string template)
    {
        // Receivers echo the rua address back with display names, brackets,
        // whitespace and arbitrary casing. A strict match drops real reports.
        var token = ReportAddress.GenerateToken();
        Assert.True(ReportAddress.TryParse(string.Format(template, token), ReportingDomain, out var parsed));
        Assert.Equal(token, parsed);
    }

    [Fact]
    public void IgnoresAPlusTag()
    {
        var token = ReportAddress.GenerateToken();
        Assert.True(ReportAddress.TryParse($"{token}+google@rua.nrgsecure.com", ReportingDomain, out var parsed));
        Assert.Equal(token, parsed);
    }

    [Fact]
    public void RefusesATokenPresentedFromAnotherDomain()
    {
        // The protection is that the attacker does not know the token. If they
        // learn one, they must not be able to replay it from their own
        // infrastructure into our ingest.
        var token = ReportAddress.GenerateToken();
        Assert.False(ReportAddress.TryParse($"{token}@rua.attacker.com", ReportingDomain, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-address")]
    [InlineData("@rua.nrgsecure.com")]
    [InlineData("token@")]
    [InlineData("dmarc@rua.nrgsecure.com")]   // valid address, not a token
    public void RefusesAnAddressItCannotVerify(string? address)
    {
        Assert.False(ReportAddress.TryParse(address, ReportingDomain, out _));
    }

    // ---- attribution: the point of the exercise ------------------------------

    private static AttributionResult Attribute(
        string deliveredTo, string reportDomain, Func<string, string?> resolve, string? fallback = null) =>
        ReportAttribution.Attribute(deliveredTo, reportDomain, ReportingDomain, resolve, fallback);

    [Fact]
    public void AttributesAReportWhenTheAddressAndTheReportAgree()
    {
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "acme.com", _ => "acme.com");

        Assert.Equal(AttributionOutcome.Attributed, result.Outcome);
        Assert.Equal("acme.com", result.Domain);
        Assert.True(result.ShouldIngest);
        Assert.False(result.IsSuspicious);
    }

    [Fact]
    public void RefusesAReportThatClaimsADifferentDomainFromTheAddressItArrivedAt()
    {
        // The whole reason per-domain addresses exist. Someone sending a
        // fabricated report for a competitor's domain to an address they
        // happened to discover must not have it filed.
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "victim.com", _ => "acme.com");

        Assert.Equal(AttributionOutcome.DomainMismatch, result.Outcome);
        Assert.False(result.ShouldIngest);
        Assert.True(result.IsSuspicious);
    }

    [Fact]
    public void ExplainsAMismatchInTermsAnOperatorCanActOn()
    {
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "victim.com", _ => "acme.com");

        Assert.Contains("acme.com", result.Reason, StringComparison.Ordinal);
        Assert.Contains("victim.com", result.Reason, StringComparison.Ordinal);
        Assert.Contains("fabricated", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TreatsAReportWithNoDomainAsAMismatchRatherThanAttributingIt()
    {
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "", _ => "acme.com");

        Assert.Equal(AttributionOutcome.DomainMismatch, result.Outcome);
        Assert.False(result.ShouldIngest);
    }

    [Fact]
    public void AcceptsASubdomainReportAtTheParentAddress()
    {
        // A subdomain's reports legitimately arrive at the parent's address,
        // because that is where the parent's DMARC record points.
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "mail.acme.com", _ => "acme.com");

        Assert.Equal(AttributionOutcome.Attributed, result.Outcome);
        Assert.Equal("acme.com", result.Domain);
    }

    [Fact]
    public void DoesNotAcceptAParentReportAtASubdomainAddress()
    {
        // The relationship only holds downward. An address issued for
        // mail.acme.com does not vouch for acme.com itself.
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "acme.com", _ => "mail.acme.com");

        Assert.Equal(AttributionOutcome.DomainMismatch, result.Outcome);
    }

    [Fact]
    public void IsNotFooledByADomainThatMerelyEndsWithTheSameLetters()
    {
        // notacme.com must not be treated as a subdomain of acme.com.
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "notacme.com", _ => "acme.com");

        Assert.Equal(AttributionOutcome.DomainMismatch, result.Outcome);
    }

    [Fact]
    public void ReportsAnAddressItNeverIssuedAsUnknownRatherThanSuspicious()
    {
        // Expected for a while after a domain is removed: receivers keep
        // sending to a published address until the record changes. Worth
        // noticing, not worth alarming about.
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "acme.com", _ => null);

        Assert.Equal(AttributionOutcome.UnknownAddress, result.Outcome);
        Assert.False(result.ShouldIngest);
        Assert.False(result.IsSuspicious);
    }

    [Fact]
    public void RejectsMailToTheReportingDomainThatIsNotAReportAddress()
    {
        var result = Attribute("hello@rua.nrgsecure.com", "acme.com", _ => "acme.com");
        Assert.Equal(AttributionOutcome.UnknownAddress, result.Outcome);
        Assert.False(result.ShouldIngest);
    }

    // ---- the shared fallback ------------------------------------------------

    [Fact]
    public void IngestsFromTheSharedAddressButMarksAttributionAsWeaker()
    {
        // A deployment that has not moved to per-domain addressing still has
        // to work. It must not be silently treated as equivalent, though.
        var result = Attribute("dmarc@nrgtechservices.com", "acme.com", _ => null, "dmarc@nrgtechservices.com");

        Assert.Equal(AttributionOutcome.FallbackAddress, result.Outcome);
        Assert.Equal("acme.com", result.Domain);
        Assert.True(result.ShouldIngest);
        Assert.Contains("own address", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PrefersAPerDomainAddressOverTheFallback()
    {
        var token = ReportAddress.GenerateToken();
        var result = Attribute($"{token}@rua.nrgsecure.com", "acme.com", _ => "acme.com", "dmarc@nrgtechservices.com");

        Assert.Equal(AttributionOutcome.Attributed, result.Outcome);
    }

    [Fact]
    public void DoesNotIngestUnrecognizedMailWhenAFallbackIsConfigured()
    {
        // A configured fallback must not become a catch-all that accepts
        // anything addressed anywhere.
        var result = Attribute("random@elsewhere.com", "acme.com", _ => null, "dmarc@nrgtechservices.com");

        Assert.Equal(AttributionOutcome.UnknownAddress, result.Outcome);
        Assert.False(result.ShouldIngest);
    }

    [Fact]
    public void NeverThrowsOnMissingOrOddInput()
    {
        string?[] addresses = [null, "", "   ", "@", "<>", "a@b@c", new string('x', 5000)];
        foreach (var a in addresses)
        {
            Assert.Null(Record.Exception(() =>
                ReportAttribution.Attribute(a, "acme.com", ReportingDomain, _ => "acme.com")));
        }
    }
}
