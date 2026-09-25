using System.Net;
using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Whether a reverse name's forward records point back at the address.
///
/// The comparison that decides whether a PTR is the owner's word or the
/// sender's claim, so it is compared as addresses: the reports and DNS need not
/// spell the same IPv6 address the same way, and a text comparison that missed
/// it would quietly stop recognizing a real gateway.
/// </summary>
public sealed class ForwardConfirmationTests
{
    private static IPAddress[] Addresses(params string[] values) => [.. values.Select(IPAddress.Parse)];

    [Fact]
    public void AnAddressAmongTheForwardRecordsIsConfirmed()
    {
        // INKY's relays: one name, several addresses behind it.
        Assert.True(DnsLookup.PointsBack(
            IPAddress.Parse("100.24.129.5"),
            Addresses("100.21.157.149", "100.24.129.5", "13.52.203.50")));
    }

    [Fact]
    public void AnAddressTheNameDoesNotListIsNotConfirmed()
    {
        // A forger reversing to mail.inkyphishfence.com: INKY's DNS names
        // INKY's servers, not the forger's.
        Assert.False(DnsLookup.PointsBack(
            IPAddress.Parse("203.0.113.66"),
            Addresses("100.21.157.149", "100.24.129.5")));
    }

    [Fact]
    public void NoForwardRecordsConfirmNothing()
    {
        Assert.False(DnsLookup.PointsBack(IPAddress.Parse("67.115.118.5"), []));
    }

    [Theory]
    [InlineData("2603:10b6:408:10a::22", "2603:10b6:408:10a:0:0:0:22")]
    [InlineData("2A01:111:F403:C112::5", "2a01:111:f403:c112::5")]
    public void TheSameIPv6AddressSpelledDifferentlyIsTheSameAddress(string reported, string published)
    {
        Assert.True(DnsLookup.PointsBack(IPAddress.Parse(reported), Addresses(published)));
    }

    [Fact]
    public void AnIPv4MappedAddressMatchesItsIPv4Form()
    {
        Assert.True(DnsLookup.PointsBack(
            IPAddress.Parse("::ffff:35.174.145.124"),
            Addresses("35.174.145.124")));
    }

    [Fact]
    public void ANeighbouringAddressIsNotConfirmed()
    {
        Assert.False(DnsLookup.PointsBack(
            IPAddress.Parse("35.174.145.125"),
            Addresses("35.174.145.124")));
    }
}
