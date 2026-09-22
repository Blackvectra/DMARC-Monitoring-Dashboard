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
