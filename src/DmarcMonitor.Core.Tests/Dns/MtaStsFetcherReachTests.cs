using System.Net;
using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Where the policy fetcher is allowed to connect.
///
/// The host it fetches is built from a domain in the book, and a domain gets
/// into the book by a report arriving for it. With a shared reporting address
/// - the documented default - the domain is taken from the report itself, and
/// that address is published in every client's DMARC record. So anybody can
/// email a report and have a domain of their choosing appear in the book,
/// then point mta-sts.&lt;that domain&gt; at whatever they like.
///
/// Certificate validation already stopped anything being read back: an
/// internal service has no certificate for somebody else's hostname. But the
/// connection was still attempted, and which way it failed said whether
/// something was listening - a port scan of the inside of the network, driven
/// by an email to a published address.
/// </summary>
public sealed class MtaStsFetcherReachTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.2.3")]
    [InlineData("0.0.0.0")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.1")]
    [InlineData("100.64.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    public void AddressesInsideTheNetworkAreRefused(string address)
    {
        Assert.True(MtaStsFetcher.IsInternal(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("169.254.169.254")]     // AWS, Azure and GCP instance metadata
    [InlineData("fd00:ec2::254")]       // the IPv6 one
    public void TheCloudMetadataAddressesAreRefusedByName(string address)
    {
        // Named on their own because they are the ones worth being sure about.
        // The certificate check would refuse them anyway; this means the
        // connection is never made at all.
        Assert.True(MtaStsFetcher.IsInternal(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("140.82.121.4")]        // github.com, where a policy really is served
    [InlineData("172.15.0.1")]          // just below the private range
    [InlineData("172.32.0.1")]          // just above it
    [InlineData("100.63.255.255")]      // just below carrier NAT
    [InlineData("100.128.0.1")]         // just above it
    [InlineData("2606:4700::1111")]
    public void PublicAddressesAreReachable(string address)
    {
        // A guard that blocks the real internet is not a guard, it is an
        // outage. The boundaries are checked from both sides for that reason.
        Assert.False(MtaStsFetcher.IsInternal(IPAddress.Parse(address)));
    }

    [Fact]
    public void AnIPv4AddressWrappedInIPv6IsStillThatAddress()
    {
        // ::ffff:127.0.0.1 is the loopback wearing a hat, and a check that
        // only looked at the v6 form would wave it through.
        Assert.True(MtaStsFetcher.IsInternal(IPAddress.Parse("::ffff:127.0.0.1")));
        Assert.True(MtaStsFetcher.IsInternal(IPAddress.Parse("::ffff:169.254.169.254")));
        Assert.False(MtaStsFetcher.IsInternal(IPAddress.Parse("::ffff:8.8.8.8")));
    }

    // ---- the decision, without a network --------------------------------------

    [Fact]
    public void AHostResolvingOnlyInwardsIsRefused()
    {
        Assert.True(MtaStsFetcher.OnlyInside([IPAddress.Parse("10.0.0.5")]));
        Assert.True(MtaStsFetcher.OnlyInside(
            [IPAddress.Parse("127.0.0.1"), IPAddress.Parse("169.254.169.254")]));
    }

    [Fact]
    public void OneReachableAddressIsEnough()
    {
        // A host that answers publicly and also carries an internal address is
        // an ordinary split-horizon arrangement, not an attack.
        Assert.False(MtaStsFetcher.OnlyInside(
            [IPAddress.Parse("10.0.0.5"), IPAddress.Parse("140.82.121.4")]));
    }

    [Fact]
    public void ANameThatResolvesToNothingIsNotCalledInternal()
    {
        // It is a policy host that does not exist, and the fetch says so in
        // its own words. Answering "inside this network" would be a sentence
        // about something nobody established.
        Assert.False(MtaStsFetcher.OnlyInside([]));
    }

    [Fact]
    public void TheHostIsTheOneRfc8461Names()
    {
        Assert.Equal("mta-sts.example.com", MtaStsFetcher.HostFor("EXAMPLE.com."));
    }

    [Fact]
    public void NullIsRefusedRatherThanTreatedAsPublic()
    {
        Assert.Throws<ArgumentNullException>(() => MtaStsFetcher.IsInternal(null!));
    }
}
