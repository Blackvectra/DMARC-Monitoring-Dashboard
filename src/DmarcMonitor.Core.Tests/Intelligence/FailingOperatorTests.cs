using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// Grouping failing sources by who operates them.
///
/// From a real import of 83 reports over 17 domains, the sources list
/// reported four separate findings, each rated Medium, each against one
/// domain:
///
///   107.175.149.54   107-175-149-54-host.colocrossing.com   ndgga.com
///   192.210.194.21   192-210-194-21-host.colocrossing.com   ndunited.org
///   198.46.243.200   198-46-243-200-host.colocrossing.com   ndunited.org
///   192.210.134.82   192-210-134-82-host.colocrossing.com   bmcedc.com
///
/// One hosting provider, four addresses, three unrelated customers. As four
/// rows it is noise. As one operator it is the finding a single-tenant tool
/// cannot make - and the per-address view misses it because changing address
/// between customers costs nothing on a VPS host.
///
/// Every reverse name below came out of that import.
/// </summary>
public sealed class FailingOperatorTests
{
    /// <summary>A failing source whose name was looked up and confirmed.</summary>
    private static FailingSource Source(string ip, string? reverseName, params string[] domains) => new()
    {
        SourceIp = ip,
        ReverseName = reverseName,
        NameConfirmed = reverseName is not null,
        FailedMessages = 1,
        Domains = domains,
        Clients = domains,
        IndependentParties = domains.Length,
    };

    /// <summary>The same, with a name its forward records do not confirm: a claim.</summary>
    private static FailingSource Claimed(string ip, string reverseName, params string[] domains) =>
        Source(ip, reverseName, domains) with { NameConfirmed = false };

    /// <summary>The case this exists for, with the real addresses.</summary>
    [Fact]
    public void FourAddressesAtOneHostAgainstThreeCustomersAreOneFinding()
    {
        var grouped = CorrelationService.ByOperator([
            Source("107.175.149.54", "107-175-149-54-host.colocrossing.com", "ndgga.com"),
            Source("192.210.194.21", "192-210-194-21-host.colocrossing.com", "ndunited.org"),
            Source("198.46.243.200", "198-46-243-200-host.colocrossing.com", "ndunited.org"),
            Source("192.210.134.82", "192-210-134-82-host.colocrossing.com", "bmcedc.com"),
        ]);

        var found = Assert.Single(grouped);
        Assert.Equal("colocrossing.com", found.Domain);
        Assert.Equal(4, found.AddressCount);
        Assert.Equal(3, found.Domains.Count);

        // The addresses are kept, not replaced: blocking is done by address.
        Assert.Contains("192.210.134.82", found.Sources.Select(s => s.SourceIp));
    }

    /// <summary>
    /// The exclusion that keeps the page usable. Grouping Microsoft produces
    /// "Microsoft 365, nine domains" on every estate on earth: true, useless,
    /// and permanently at the top.
    /// </summary>
    [Fact]
    public void AMailProviderIsInfrastructureRatherThanAnActor()
    {
        var grouped = CorrelationService.ByOperator([
            Source("2a01:111:f403:c112::5", "mail-westcentralusazlp170100005.outbound.protection.outlook.com", "a.example"),
            Source("2a01:111:f403:c107::1", "mail-westus3azlp170120001.outbound.protection.outlook.com", "b.example"),
        ]);

        Assert.Empty(grouped);
    }

    /// <summary>
    /// Only where the name is confirmed. Grouping is by the domain each
    /// address claims, and a sender forging mail can reverse to
    /// something.outlook.com: taken at its word, the whole group vanished from
    /// the page as "infrastructure".
    /// </summary>
    [Fact]
    public void ClaimingToBeAMailProviderDoesNotHideACampaign()
    {
        var grouped = CorrelationService.ByOperator([
            Claimed("203.0.113.10", "mail1.outbound.protection.outlook.com", "a.example"),
            Claimed("203.0.113.11", "mail2.outbound.protection.outlook.com", "b.example"),
        ]);

        var found = Assert.Single(grouped);
        Assert.Equal(SourceKind.Unknown, found.Kind);
        Assert.Equal("outlook.com", found.Name);
    }

    /// <summary>
    /// And a group is named for the vendor only when every address in it is
    /// confirmed as the vendor's. One claimant in it and "INKY" would vouch
    /// for the claim.
    /// </summary>
    [Fact]
    public void AGroupIsNamedForTheVendorOnlyWhenEveryAddressIsConfirmed()
    {
        var grouped = CorrelationService.ByOperator([
            Source("100.24.129.5", "ipw-outbound.inkyphishfence.com", "a.example"),
            Claimed("203.0.113.12", "mail.inkyphishfence.com", "b.example"),
        ]);

        var found = Assert.Single(grouped);
        Assert.Equal("inkyphishfence.com", found.Name);
        Assert.Equal(SourceKind.Unknown, found.Kind);
    }

    /// <summary>
    /// Gateways are kept, though. A gateway breaking signatures across five
    /// customers is a real finding, and one an MSP is uniquely placed to see.
    /// </summary>
    [Fact]
    public void AGatewayAcrossSeveralCustomersIsStillWorthGrouping()
    {
        var grouped = CorrelationService.ByOperator([
            Source("35.174.145.124", "us.cloud-sec-av.com", "dmvwrr.com"),
            Source("35.174.145.125", "eu.cloud-sec-av.com", "redriverrc.com"),
        ]);

        var found = Assert.Single(grouped);
        Assert.Equal(SourceKind.SecurityGateway, found.Kind);
        Assert.Equal(2, found.Domains.Count);
    }

    [Fact]
    public void OneAddressIsNotAGroup()
    {
        // The row for that address already says everything this would.
        var grouped = CorrelationService.ByOperator([
            Source("107.175.149.54", "107-175-149-54-host.colocrossing.com", "a.example", "b.example"),
        ]);

        Assert.Empty(grouped);
    }

    [Fact]
    public void SeveralAddressesAgainstOneDomainAreNotAFinding()
    {
        // Ordinary: it is what any mail provider looks like to one customer.
        // The finding is one operator reaching customers unrelated to each other.
        var grouped = CorrelationService.ByOperator([
            Source("107.175.149.54", "107-175-149-54-host.colocrossing.com", "only.example"),
            Source("192.210.194.21", "192-210-194-21-host.colocrossing.com", "only.example"),
        ]);

        Assert.Empty(grouped);
    }

    [Fact]
    public void AnAddressNothingHasResolvedCannotBeGrouped()
    {
        var grouped = CorrelationService.ByOperator([
            Source("203.0.113.1", null, "a.example"),
            Source("203.0.113.2", null, "b.example"),
        ]);

        Assert.Empty(grouped);
    }

    /// <summary>
    /// Reverse zones are not collapsed into one bucket. Without the
    /// two-part-suffix handling in OrganizationalDomain, every address whose
    /// PTR is only its own reverse zone would group under in-addr.arpa - and
    /// every judgement about that bucket would follow.
    /// </summary>
    [Fact]
    public void ReverseZonesDoNotBecomeOneEnormousOperator()
    {
        var grouped = CorrelationService.ByOperator([
            Source("149.0.0.1", "1.0.0.149.in-addr.arpa", "a.example"),
            Source("203.0.0.1", "1.0.0.203.in-addr.arpa", "b.example"),
        ]);

        Assert.Empty(grouped);
    }

    /// <summary>
    /// The group does not get a softer reading than its members: one address
    /// authenticating for itself does not excuse the three beside it that
    /// authenticated nothing.
    /// </summary>
    [Fact]
    public void TheGroupTakesTheWorstVerdictAmongItsAddresses()
    {
        var benign = Source("192.210.194.21", "192-210-194-21-host.colocrossing.com", "a.example")
            with { AuthenticatedFor = ["someservice.example"] };

        var grouped = CorrelationService.ByOperator([
            benign,
            Source("107.175.149.54", "107-175-149-54-host.colocrossing.com", "b.example"),
        ]);

        var found = Assert.Single(grouped);
        Assert.Equal(SourceVerdict.Unauthenticated, found.Verdict);
    }

    /// <summary>
    /// Reach first, then volume. An operator against five customers matters
    /// more than one against two, whatever the message counts say.
    /// </summary>
    [Fact]
    public void ReachOutranksVolume()
    {
        var grouped = CorrelationService.ByOperator([
            Source("198.51.100.1", "a.loud.example", "one.example") with { FailedMessages = 10_000 },
            Source("198.51.100.2", "b.loud.example", "one.example") with { FailedMessages = 10_000 },
            Source("203.0.113.1", "a.wide.example", "x.example"),
            Source("203.0.113.2", "b.wide.example", "y.example"),
            Source("203.0.113.3", "c.wide.example", "z.example"),
        ]);

        Assert.Equal("wide.example", grouped[0].Domain);
    }

    [Fact]
    public void NothingInNothingOut()
    {
        Assert.Empty(CorrelationService.ByOperator([]));
    }
}
