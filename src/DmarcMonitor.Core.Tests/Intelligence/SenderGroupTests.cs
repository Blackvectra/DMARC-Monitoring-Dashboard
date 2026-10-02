using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// Grouping failing sources by who operates them, and ordering the result.
///
/// From a real import, the sources list reported four separate findings,
/// each rated Medium, each against one domain:
///
///   192.0.2.10   192-0-2-10-host.colocrossing.com   alpha.example
///   192.0.2.11   192-0-2-11-host.colocrossing.com   bravo.example
///   192.0.2.12   192-0-2-12-host.colocrossing.com   bravo.example
///   192.0.2.13   192-0-2-13-host.colocrossing.com   charlie.example
///
/// One hosting provider, four addresses, three unrelated customers. As four
/// rows it is noise. As one sender it is the finding a single-tenant tool
/// cannot make - and the per-address view misses it because changing address
/// between customers costs nothing on a VPS host.
///
/// The names below have that shape; the addresses and domains are documentation placeholders.
/// </summary>
public sealed class SenderGroupTests
{
    /// <summary>A failing source whose name was looked up and confirmed, each domain its own party.</summary>
    private static FailingSource Source(string ip, string? reverseName, params string[] domains) => new()
    {
        SourceIp = ip,
        ReverseName = reverseName,
        NameConfirmed = reverseName is not null,
        FailedMessages = 1,
        Domains = domains,
        Clients = domains,
        IndependentParties = domains.Length,
        PartyKeys = [.. domains.Select(d => $"client:{d}")],
    };

    /// <summary>The same, with a name its forward records do not confirm: a claim.</summary>
    private static FailingSource Claimed(string ip, string reverseName, params string[] domains) =>
        Source(ip, reverseName, domains) with { NameConfirmed = false };

    // ---- who belongs together ------------------------------------------------

    /// <summary>The case this exists for, with the real addresses.</summary>
    [Fact]
    public void FourAddressesAtOneHostAgainstThreeCustomersAreOneSender()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("192.0.2.10", "192-0-2-10-host.colocrossing.com", "alpha.example"),
            Source("192.0.2.11", "192-0-2-11-host.colocrossing.com", "bravo.example"),
            Source("192.0.2.12", "192-0-2-12-host.colocrossing.com", "bravo.example"),
            Source("192.0.2.13", "192-0-2-13-host.colocrossing.com", "charlie.example"),
        ]));

        Assert.Equal("colocrossing.com", found.Domain);
        Assert.Equal(4, found.AddressCount);
        Assert.Equal(3, found.Domains.Count);
        Assert.True(found.IsGroup);
        Assert.True(found.SpansClients);

        // The addresses are kept, not replaced: blocking is done by address.
        Assert.Contains("192.0.2.13", found.Sources.Select(s => s.SourceIp));
    }

    /// <summary>
    /// A mail provider is one row rather than fourteen, and never a finding.
    /// Grouping Microsoft as an operator produces "Microsoft 365, nine
    /// clients" on every estate on earth: true, useless, and permanently at
    /// the top.
    /// </summary>
    [Fact]
    public void AMailProviderIsFoldedIntoOneRowAndIsNeverAFinding()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("2a01:111:f403:c112::5", "mail-westcentralusazlp170100005.outbound.protection.outlook.com", "a.example"),
            Source("2a01:111:f403:c107::1", "mail-westus3azlp170120001.outbound.protection.outlook.com", "b.example"),
        ]));

        Assert.Equal("Microsoft 365", found.Name);
        Assert.Equal(SourceKind.MailProvider, found.Kind);
        Assert.Equal(2, found.AddressCount);
        Assert.False(found.SpansClients);
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
        var found = Assert.Single(SenderGroup.Build([
            Claimed("203.0.113.10", "mail1.outbound.protection.outlook.com", "a.example"),
            Claimed("203.0.113.11", "mail2.outbound.protection.outlook.com", "b.example"),
        ]));

        Assert.Equal(SourceKind.Unknown, found.Kind);
        Assert.Equal("outlook.com", found.Name);
        Assert.True(found.SpansClients);
    }

    /// <summary>
    /// And a claimant is not folded into the real ones, which would lose it
    /// among them: the confirmed addresses are Microsoft's row, and the one
    /// that merely says so keeps a row of its own, under the name it claims.
    /// </summary>
    [Fact]
    public void AClaimantIsNeverLostInsideAConfirmedProvider()
    {
        var groups = SenderGroup.Build([
            Source("2a01:111:f403:c112::5", "mail-a.outbound.protection.outlook.com", "a.example"),
            Source("2a01:111:f403:c107::1", "mail-b.outbound.protection.outlook.com", "b.example"),
            Claimed("203.0.113.66", "mail.outlook.com", "c.example"),
        ]);

        Assert.Equal(2, groups.Count);
        var provider = Assert.Single(groups, g => g.IsGroup);
        Assert.Equal("Microsoft 365", provider.Name);
        Assert.DoesNotContain("203.0.113.66", provider.Sources.Select(s => s.SourceIp));

        var claimant = Assert.Single(groups, g => !g.IsGroup);
        Assert.Equal("mail.outlook.com", claimant.Name);
    }

    /// <summary>
    /// Google answers from google.com and googlemail.com. One vendor is one
    /// row, whichever of its domains an address reverses under.
    /// </summary>
    [Fact]
    public void OneProviderUnderTwoDomainsIsOneRow()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("209.85.220.41", "mail-sor-f41.google.com", "a.example"),
            Source("209.85.128.1", "mail-wm1-f1.googlemail.com", "b.example"),
        ]));

        Assert.Equal("Google", found.Name);
        Assert.Equal(2, found.AddressCount);
    }

    /// <summary>
    /// A group is named for the vendor only when every address in it is
    /// confirmed as the vendor's. One claimant in it and "INKY" would vouch
    /// for the claim.
    /// </summary>
    [Fact]
    public void AGroupIsNamedForTheVendorOnlyWhenEveryAddressIsConfirmed()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("100.24.129.5", "ipw-outbound.inkyphishfence.com", "a.example"),
            Claimed("203.0.113.12", "mail.inkyphishfence.com", "b.example"),
        ]));

        Assert.Equal("inkyphishfence.com", found.Name);
        Assert.Equal(SourceKind.Unknown, found.Kind);
    }

    [Fact]
    public void AGroupWhoseEveryAddressIsConfirmedIsNamedForTheVendor()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("100.24.129.5", "ipw-outbound.inkyphishfence.com", "a.example"),
            Source("100.24.129.6", "ipw-outbound2.inkyphishfence.com", "b.example"),
        ]));

        Assert.Equal("INKY", found.Name);
        Assert.Equal(SourceKind.SecurityGateway, found.Kind);
    }

    /// <summary>
    /// Gateways are kept, though. A gateway breaking signatures across five
    /// customers is a real finding, and one an MSP is uniquely placed to see.
    /// </summary>
    [Fact]
    public void AGatewayAcrossSeveralCustomersIsStillAFinding()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("198.51.100.124", "us.cloud-sec-av.com", "delta.example"),
            Source("198.51.100.125", "eu.cloud-sec-av.com", "echo.example"),
        ]));

        Assert.Equal(SourceKind.SecurityGateway, found.Kind);
        Assert.Equal(2, found.Domains.Count);
        Assert.True(found.SpansClients);
    }

    [Fact]
    public void OneAddressIsNotAGroup()
    {
        // The row for that address says everything a group would, and reads
        // exactly as it always did.
        var only = Assert.Single(SenderGroup.Build([
            Source("192.0.2.10", "192-0-2-10-host.colocrossing.com", "a.example", "b.example"),
        ]));

        Assert.False(only.IsGroup);
        Assert.Equal(only.Sources[0].Display, only.Name);
        Assert.Null(only.Domain);
        Assert.False(only.SpansClients);
    }

    [Fact]
    public void SeveralAddressesAgainstOneDomainAreNotSpanningClients()
    {
        // Ordinary: it is what any mail provider looks like to one customer.
        // The finding is one operator reaching customers unrelated to each other.
        var found = Assert.Single(SenderGroup.Build([
            Source("192.0.2.10", "192-0-2-10-host.colocrossing.com", "only.example"),
            Source("192.0.2.11", "192-0-2-11-host.colocrossing.com", "only.example"),
        ]));

        Assert.True(found.IsGroup);
        Assert.False(found.SpansClients);
    }

    /// <summary>
    /// One client with two domains is one party. An operator that hit both is
    /// not working through a list of customers.
    /// </summary>
    [Fact]
    public void TwoDomainsOfOneClientAreOnePartyNotACampaign()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("192.0.2.10", "a-host.colocrossing.com", "pair-one.example") with { PartyKeys = ["client:pair"], IndependentParties = 1 },
            Source("192.0.2.11", "b-host.colocrossing.com", "pair-two.example") with { PartyKeys = ["client:pair"], IndependentParties = 1 },
        ]));

        Assert.Equal(2, found.Domains.Count);
        Assert.Equal(1, found.IndependentParties);
        Assert.False(found.SpansClients);
    }

    /// <summary>
    /// Counted once each: neither the sum, which double counts a client two
    /// addresses both reached, nor the largest, which misses the parties they
    /// did not share.
    /// </summary>
    [Fact]
    public void TheSenderReachedTheUnionOfWhatItsAddressesReached()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("203.0.113.1", "a.shared.example", "x.example", "y.example"),
            Source("203.0.113.2", "b.shared.example", "y.example", "z.example"),
        ]));

        Assert.Equal(3, found.IndependentParties);
    }

    /// <summary>
    /// Rows built without party keys - an older caller, a hand-built test -
    /// still get a count, the largest of theirs, rather than a crash or a zero.
    /// </summary>
    [Fact]
    public void WithoutPartyKeysTheLargestCountStands()
    {
        var found = Assert.Single(SenderGroup.Build([
            Source("203.0.113.1", "a.shared.example", "x.example", "y.example") with { PartyKeys = [] },
            Source("203.0.113.2", "b.shared.example", "z.example") with { PartyKeys = [] },
        ]));

        Assert.Equal(2, found.IndependentParties);
    }

    [Fact]
    public void AnAddressNothingHasResolvedStaysARowOfItsOwn()
    {
        var groups = SenderGroup.Build([
            Source("203.0.113.1", null, "a.example"),
            Source("203.0.113.2", null, "b.example"),
        ]);

        Assert.Equal(2, groups.Count);
        Assert.All(groups, g => Assert.False(g.IsGroup));
        Assert.Equal(["203.0.113.1", "203.0.113.2"], groups.Select(g => g.Name));
    }

    /// <summary>
    /// Reverse zones are not collapsed into one bucket. Without the guard,
    /// every address whose PTR is only its own reverse zone would group under
    /// its leading octet - and every judgement about that bucket would follow.
    /// </summary>
    [Fact]
    public void ReverseZonesDoNotBecomeOneEnormousSender()
    {
        var groups = SenderGroup.Build([
            Source("149.0.0.1", "1.0.0.149.in-addr.arpa", "a.example"),
            Source("149.0.0.2", "2.0.0.149.in-addr.arpa", "b.example"),
        ]);

        Assert.Equal(2, groups.Count);
        Assert.All(groups, g => Assert.False(g.IsGroup));
    }

    /// <summary>
    /// For the person who wants the old list: one row per address, nothing
    /// folded.
    /// </summary>
    [Fact]
    public void UngroupedKeepsEveryAddressAlone()
    {
        var groups = SenderGroup.Build([
            Source("192.0.2.10", "a-host.colocrossing.com", "a.example"),
            Source("192.0.2.11", "b-host.colocrossing.com", "b.example"),
        ], group: false);

        Assert.Equal(2, groups.Count);
        Assert.All(groups, g => Assert.False(g.IsGroup));
    }

    [Fact]
    public void KeysAreUniqueSoARowCanBeToldFromItsNeighbour()
    {
        var groups = SenderGroup.Build([
            Source("192.0.2.10", "a-host.colocrossing.com", "a.example"),
            Source("192.0.2.11", "b-host.colocrossing.com", "b.example"),
            Source("203.0.113.1", null, "c.example"),
            Source("203.0.113.2", null, "d.example"),
        ]);

        Assert.Equal(groups.Count, groups.Select(g => g.Key).Distinct().Count());
    }

    [Fact]
    public void NothingInNothingOut()
    {
        Assert.Empty(SenderGroup.Build([]));
        Assert.Empty(SenderGroup.Order([], SenderSort.Severity, descending: true));
    }

    // ---- what a group is rated ----------------------------------------------

    /// <summary>
    /// The group does not get a softer reading than its members: one address
    /// authenticating for itself does not excuse the three beside it that
    /// authenticated nothing.
    /// </summary>
    [Fact]
    public void TheGroupTakesTheWorstVerdictAmongItsAddresses()
    {
        var benign = Source("192.0.2.11", "192-0-2-11-host.colocrossing.com", "a.example")
            with { AuthenticatedFor = ["someservice.example"] };

        var found = Assert.Single(SenderGroup.Build([
            benign,
            Source("192.0.2.10", "192-0-2-10-host.colocrossing.com", "b.example"),
        ]));

        Assert.Equal(SourceVerdict.Unauthenticated, found.Verdict);
        Assert.Equal(SourceReading.Unauthenticated, found.Reading);
    }

    [Fact]
    public void AnAddressRelayingForTheClientIsReadAsItsOwnSendingPath()
    {
        var relay = Source("198.51.100.124", "us.cloud-sec-av.com", "one.example", "two.example")
            with { DomainsAlsoPassed = 2 };

        Assert.True(relay.IsOwnSendingPath);
        Assert.Equal(SourceReading.OwnSendingPath, relay.Reading);
    }

    /// <summary>
    /// A real service signing as its own domain is fixed at the vendor, not at
    /// the gateway - the reason the two halves of "misconfigured" are told
    /// apart.
    /// </summary>
    [Fact]
    public void AServiceSigningAsItselfIsReadAsUnaligned()
    {
        var service = Source("198.51.100.7", "mail.sender.example", "acme.example")
            with { AuthenticatedFor = ["mailchimpapp.net"] };

        Assert.Equal(SourceVerdict.Misconfigured, service.Verdict);
        Assert.Equal(SourceReading.Unaligned, service.Reading);
    }

    [Fact]
    public void AnOwnSendingPathIsReadAsOneWhateverElseItAuthenticatedFor()
    {
        // Passed for every domain it fails against, so it is one of the
        // client's own paths however its failing rows happened to authenticate.
        var relay = Source("198.51.100.124", "us.cloud-sec-av.com", "one.example")
            with { DomainsAlsoPassed = 1, AuthenticatedFor = ["gateway.example"] };

        Assert.Equal(SourceReading.OwnSendingPath, relay.Reading);
    }

    [Fact]
    public void AuthenticatingNothingAgainstSeveralPartiesIsReadAsCrossClient()
    {
        var forger = Source("203.0.113.9", null, "a.example", "b.example");

        Assert.Equal(SourceReading.CrossClient, forger.Reading);
    }

    // ---- ordering ------------------------------------------------------------

    private static SenderGroup Lone(
        string ip, SourceReading reading, long failed = 1, DateTimeOffset? lastSeen = null, string? name = null)
    {
        var source = Source(ip, name is null ? null : $"{name}.example", "a.example") with
        {
            FailedMessages = failed,
            LastSeen = lastSeen,
            NameConfirmed = false,
        };

        source = reading switch
        {
            SourceReading.CrossClient => source with { IndependentParties = 3, PartyKeys = ["client:a", "client:b", "client:c"] },
            SourceReading.Unaligned => source with { AuthenticatedFor = ["vendor.example"] },
            SourceReading.OwnSendingPath => source with { DomainsAlsoPassed = 1 },
            _ => source,
        };

        Assert.Equal(reading, source.Reading);
        return Assert.Single(SenderGroup.Build([source]));
    }

    [Fact]
    public void TheWorstReadingComesFirst()
    {
        var ordered = SenderGroup.Order([
            Lone("192.0.2.1", SourceReading.OwnSendingPath, failed: 9_000),
            Lone("192.0.2.2", SourceReading.CrossClient),
            Lone("192.0.2.3", SourceReading.Unaligned, failed: 500),
            Lone("192.0.2.4", SourceReading.Unauthenticated),
        ], SenderSort.Severity, descending: true);

        // Volume does not outrank severity: nine thousand broken-in-transit
        // messages from a client's own relay are not the finding.
        Assert.Equal(
            [SourceReading.CrossClient, SourceReading.Unauthenticated, SourceReading.Unaligned, SourceReading.OwnSendingPath],
            ordered.Select(g => g.Reading));
    }

    /// <summary>
    /// Reach first, then volume: an operator against five customers matters
    /// more than one against two, whatever the message counts say.
    /// </summary>
    [Fact]
    public void ReachOutranksVolume()
    {
        var ordered = SenderGroup.Order(SenderGroup.Build([
            Source("198.51.100.1", "a.loud.example", "one.example") with { FailedMessages = 10_000 },
            Source("198.51.100.2", "b.loud.example", "one.example") with { FailedMessages = 10_000 },
            Source("203.0.113.1", "a.wide.example", "x.example"),
            Source("203.0.113.2", "b.wide.example", "y.example"),
            Source("203.0.113.3", "c.wide.example", "z.example"),
        ]), SenderSort.Severity, descending: true);

        Assert.Equal("wide.example", ordered[0].Domain);
    }

    [Fact]
    public void FlippingTheDirectionReversesTheColumnAndNothingElse()
    {
        SenderGroup[] groups =
        [
            Lone("192.0.2.1", SourceReading.Unauthenticated, failed: 5),
            Lone("192.0.2.2", SourceReading.Unauthenticated, failed: 50),
            Lone("192.0.2.3", SourceReading.Unauthenticated, failed: 500),
        ];

        Assert.Equal([500L, 50, 5], SenderGroup.Order(groups, SenderSort.Failed, descending: true).Select(g => g.FailedMessages));
        Assert.Equal([5L, 50, 500], SenderGroup.Order(groups, SenderSort.Failed, descending: false).Select(g => g.FailedMessages));
    }

    [Fact]
    public void EqualRowsKeepTheSameOrderWhicheverWayTheColumnRuns()
    {
        // Three tied on volume. Reversing the column must not reshuffle them:
        // a list that rearranges its equal rows on every click looks broken.
        SenderGroup[] groups =
        [
            Lone("192.0.2.3", SourceReading.Unauthenticated, failed: 7),
            Lone("192.0.2.1", SourceReading.Unauthenticated, failed: 7),
            Lone("192.0.2.2", SourceReading.Unauthenticated, failed: 7),
        ];

        var down = SenderGroup.Order(groups, SenderSort.Failed, descending: true).Select(g => g.Key);
        var up = SenderGroup.Order(groups, SenderSort.Failed, descending: false).Select(g => g.Key);

        Assert.Equal(down, up);
    }

    [Fact]
    public void SenderNamesSortWithoutRegardToCase()
    {
        var ordered = SenderGroup.Order([
            Lone("192.0.2.1", SourceReading.Unauthenticated, name: "beta"),
            Lone("192.0.2.2", SourceReading.Unauthenticated, name: "Alpha"),
            Lone("192.0.2.3", SourceReading.Unauthenticated, name: "gamma"),
        ], SenderSort.Sender, descending: false);

        Assert.Equal(["Alpha.example", "beta.example", "gamma.example"], ordered.Select(g => g.Name));
    }

    /// <summary>
    /// Never seen sorts as the oldest, so "newest first" ends with the unknown
    /// rather than opening with them.
    /// </summary>
    [Fact]
    public void AnUndatedSenderSortsAsTheOldest()
    {
        var now = DateTimeOffset.UtcNow;
        var ordered = SenderGroup.Order([
            Lone("192.0.2.1", SourceReading.Unauthenticated, lastSeen: null),
            Lone("192.0.2.2", SourceReading.Unauthenticated, lastSeen: now.AddDays(-9)),
            Lone("192.0.2.3", SourceReading.Unauthenticated, lastSeen: now.AddDays(-1)),
        ], SenderSort.LastSeen, descending: true);

        Assert.Equal(["192.0.2.3", "192.0.2.2", "192.0.2.1"], ordered.Select(g => g.Sources[0].SourceIp));
    }

    [Fact]
    public void AGroupsLastSeenIsTheNewestOfItsAddresses()
    {
        var now = DateTimeOffset.UtcNow;
        var found = Assert.Single(SenderGroup.Build([
            Source("192.0.2.10", "a-host.colocrossing.com", "a.example") with { LastSeen = now.AddDays(-9) },
            Source("192.0.2.11", "b-host.colocrossing.com", "b.example") with { LastSeen = now.AddDays(-2) },
        ]));

        Assert.Equal(now.AddDays(-2), found.LastSeen);
    }
}
