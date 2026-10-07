using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// Naming a sending source from its reverse-DNS name.
///
/// Every host name below is one that actually appeared in a week of reports
/// for a real estate, taken from the reverse lookups and from a commercial
/// platform's own export of the same window. That matters more than invented
/// examples would: the shapes reverse DNS takes in practice - a fifty
/// character Azure hostname, a hyphenated address embedded in a hosting
/// provider's domain, a name that is only the reverse zone - are the whole
/// difficulty, and none of them look like example.com.
/// </summary>
public sealed class SourceCatalogTests
{
    [Theory]
    // The long ones. Microsoft's outbound names carry region and scale unit,
    // and reduce to one organizational domain like anything else.
    [InlineData("mail-eastus2azlp170110003.outbound.protection.outlook.com", "outlook.com")]
    [InlineData("mail-westcentralusazon11023141.outbound.protection.outlook.com", "outlook.com")]
    [InlineData("us.cloud-sec-av.com", "cloud-sec-av.com")]
    [InlineData("ipw-outbound.inkyphishfence.com", "inkyphishfence.com")]
    [InlineData("192-3-180-38-host.colocrossing.com", "colocrossing.com")]
    [InlineData("vmi3366424.contaboserver.net", "contaboserver.net")]
    [InlineData("mail-sor-f41.google.com", "google.com")]
    [InlineData("itdmail1.nd.gov", "nd.gov")]
    [InlineData("o6.ptr5219.mediaoutreach.meltwater.com", "meltwater.com")]
    [InlineData("mta-80-125.sparkpostmail.com", "sparkpostmail.com")]
    // Already registrable.
    [InlineData("outlook.com", "outlook.com")]
    public void ReducesAHostNameToItsOrganizationalDomain(string host, string expected) =>
        Assert.Equal(expected, SourceCatalog.OrganizationalDomain(host));

    /// <summary>
    /// The case that would otherwise put every unnamed address on the internet
    /// into a single bucket called "in-addr.arpa", and with it every judgement
    /// made about that bucket.
    /// </summary>
    [Theory]
    [InlineData("158.151.62.149.in-addr.arpa", "149.in-addr.arpa")]
    [InlineData("1.0.0.127.in-addr.arpa", "127.in-addr.arpa")]
    public void KeepsReverseZonesApart(string host, string expected) =>
        Assert.Equal(expected, SourceCatalog.OrganizationalDomain(host));

    [Theory]
    [InlineData("mail.example.co.uk", "example.co.uk")]
    [InlineData("smtp.thing.com.au", "thing.com.au")]
    public void TreatsATwoPartSuffixAsASuffix(string host, string expected) =>
        Assert.Equal(expected, SourceCatalog.OrganizationalDomain(host));

    /// <summary>
    /// The reduction is now a grouping key, so a suffix missing from the list
    /// is not just an unnamed source: it is two unrelated ISPs reduced to the
    /// same "domain" and shown as one sender reaching several clients.
    /// </summary>
    [Theory]
    [InlineData("p1234-ipngn100101osakachuo.osaka.ocn.ne.jp", "ocn.ne.jp")]
    [InlineData("kd027083045012.au-net.ne.jp", "au-net.ne.jp")]
    [InlineData("host.example.or.jp", "example.or.jp")]
    [InlineData("static.example.net.br", "example.net.br")]
    [InlineData("mail.example.com.cn", "example.com.cn")]
    [InlineData("host.example.com.tr", "example.com.tr")]
    [InlineData("host.example.co.kr", "example.co.kr")]
    [InlineData("host.example.co.th", "example.co.th")]
    [InlineData("host.example.net.in", "example.net.in")]
    [InlineData("host.example.com.tw", "example.com.tw")]
    public void TreatsTheCommonCountrySuffixesAsSuffixes(string host, string expected) =>
        Assert.Equal(expected, SourceCatalog.OrganizationalDomain(host));

    [Theory]
    [InlineData("ne.jp")]
    [InlineData("co.kr")]
    // Not on the list, and the reason the guard exists: a two-letter country
    // code over a label of three letters or fewer is nearly always a registry.
    [InlineData("com.pg")]
    [InlineData("ya.ru")]
    public void RecognizesWhatLooksLikeAPublicSuffix(string domain) =>
        Assert.True(SourceCatalog.LooksLikeAPublicSuffix(domain));

    [Theory]
    [InlineData("colocrossing.com")]
    [InlineData("nd.gov")]
    [InlineData("ocn.ne.jp")]
    [InlineData("example.co.uk")]
    [InlineData("hetzner.de")]
    [InlineData("in-addr.arpa")]
    [InlineData(null)]
    [InlineData("")]
    public void DoesNotMistakeARegistrableDomainForASuffix(string? domain) =>
        Assert.False(SourceCatalog.LooksLikeAPublicSuffix(domain));

    /// <summary>
    /// One vendor is one name, whichever of its domains an address reverses
    /// under; the catalogue says so, and the grouping follows it.
    /// </summary>
    [Theory]
    [InlineData("contaboserver.net", "contabo.net")]
    [InlineData("hetzner.de", "hetzner.com")]
    [InlineData("1and1.com", "ionos.com")]
    [InlineData("mcsv.net", "mailchimp.com")]
    [InlineData("googlemail.com", "google.com")]
    public void AVendorThatAnswersFromTwoDomainsHasOneMainDomain(string alias, string main)
    {
        Assert.Equal(main, SourceCatalog.CanonicalDomain(alias));
        Assert.Equal(main, SourceCatalog.CanonicalDomain(main));

        // And the catalogue agrees they are the same vendor, so the alias
        // table cannot drift from the names.
        Assert.Equal(SourceCatalog.Identify($"host.{main}")!.Value.Name, SourceCatalog.Identify($"host.{alias}")!.Value.Name);
    }

    [Theory]
    [InlineData("colocrossing.com")]
    [InlineData("some-isp.example")]
    public void ADomainWithNoAliasIsItsOwnMainDomain(string domain) =>
        Assert.Equal(domain, SourceCatalog.CanonicalDomain(domain));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    public void HasNoAnswerForSomethingThatIsNotAHostName(string? host) =>
        Assert.Null(SourceCatalog.OrganizationalDomain(host));

    /// <summary>
    /// The names, and the kind - which is the part that changes what an
    /// operator does. A gateway failing is not a DNS problem and must not be
    /// read as one.
    /// </summary>
    [Theory]
    [InlineData("mail-eastus2azlp170110003.outbound.protection.outlook.com", "Microsoft 365", SourceKind.MailProvider)]
    [InlineData("us.cloud-sec-av.com", "Avanan (Check Point Harmony)", SourceKind.SecurityGateway)]
    [InlineData("ipw-outbound.inkyphishfence.com", "INKY", SourceKind.SecurityGateway)]
    [InlineData("users.sonicwall.com", "SonicWall", SourceKind.SecurityGateway)]
    [InlineData("esa9.hc3550-4.iphmx.com", "Cisco IronPort", SourceKind.SecurityGateway)]
    [InlineData("o6.ptr5219.mediaoutreach.meltwater.com", "Meltwater", SourceKind.Marketing)]
    [InlineData("mta-80-125.sparkpostmail.com", "SparkPost", SourceKind.Marketing)]
    [InlineData("192-3-180-38-host.colocrossing.com", "ColoCrossing", SourceKind.Hosting)]
    [InlineData("vmi3366424.contaboserver.net", "Contabo", SourceKind.Hosting)]
    public void NamesASourceAndSaysWhatKindItIs(string reverseName, string name, SourceKind kind)
    {
        var identity = SourceCatalog.Identify(reverseName);

        Assert.NotNull(identity);
        Assert.Equal(name, identity.Value.Name);
        Assert.Equal(kind, identity.Value.Kind);
    }

    /// <summary>
    /// Unnamed rather than guessed. A source the catalog does not hold is
    /// reported as the address it is, which is the truth; inventing a name
    /// from the host string would put a label an operator trusts on something
    /// nobody checked.
    /// </summary>
    [Theory]
    [InlineData("itdmail1.nd.gov")]
    [InlineData("158.151.62.149.in-addr.arpa")]
    [InlineData("some.company.example")]
    [InlineData(null)]
    public void SaysNothingAboutASourceItDoesNotKnow(string? reverseName) =>
        Assert.Null(SourceCatalog.Identify(reverseName));
}
