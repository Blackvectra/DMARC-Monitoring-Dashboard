using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// Telling mail a gateway broke from mail somebody forged.
///
/// Against a real book of sixteen domains these are the two largest groups of
/// DMARC failures and they need opposite responses: one hosted gateway
/// accounted for half of every failure across eleven domains, and eighteen
/// addresses in one hosting range accounted for the forgery, eight of them
/// against more than one customer. Folded into a single red percentage, a
/// domain whose seven messages were three real and four forged reads as
/// "42.9% compliant", which sounds like a broken domain and is not one.
///
/// The tests that matter most are the ones that refuse to classify. An address
/// nobody can name is not thereby hostile, and a product that says otherwise
/// is one an operator learns to discount.
/// </summary>
public sealed class FailureClassifierTests
{
    private static FailingSourceFacts Source(
        string ip = "203.0.113.5",
        string[]? envelope = null,
        bool authenticated = false,
        long passing = 0,
        int otherClients = 0) => new()
    {
        SourceIp = ip,
        EnvelopeDomains = envelope ?? [],
        Authenticated = authenticated,
        Passing = passing,
        OtherClients = otherClients,
    };

    // ---- gateways --------------------------------------------------------------

    [Theory]
    [InlineData("ipw.inkyphishfence.com")]
    [InlineData("us.cloud-sec-av.com")]
    [InlineData("courier.shield.security")]
    [InlineData("mail.mimecast.com")]
    [InlineData("pphosted.com")]
    public void AGatewayIsRecognizedByTheEnvelopeItSendsFrom(string envelope)
    {
        // The envelope rather than the address, because a cloud gateway's
        // addresses change without notice and the domain it puts in MAIL FROM
        // does not. An address table would be stale within a month.
        Assert.Equal(FailureKind.Forwarded, FailureClassifier.Classify(Source(envelope: [envelope])));
    }

    [Fact]
    public void AGatewayIsStillAGatewayWhenItIsAlsoSendingForOtherClients()
    {
        // An MSP's gateway serves every customer, so it hits the same
        // cross-client pattern that otherwise means forgery. Being able to
        // name it outranks the pattern.
        var facts = Source(envelope: ["us.cloud-sec-av.com"], otherClients: 10);

        Assert.Equal(FailureKind.Forwarded, FailureClassifier.Classify(facts));
    }

    /// <summary>
    /// The name comes from the one catalog, so a gateway is called the same
    /// thing wherever it appears.
    /// </summary>
    /// <remarks>
    /// This asserted "INKY Phish Fence" while the Sources page, reading the
    /// catalog, said "INKY" - the same address under two names depending on
    /// which page asked. The catalog is the survivor.
    /// </remarks>
    [Fact]
    public void AGatewayCanBeNamedSoThePageDoesNotJustSayForwarded()
    {
        Assert.Equal("INKY", FailureClassifier.GatewayName(["ipw.inkyphishfence.com"]));
    }

    /// <summary>
    /// And the classifier inherits everything the catalog knows, rather than
    /// keeping a shorter list of its own.
    /// </summary>
    /// <remarks>
    /// These four were in the catalog and not in the table this used to carry,
    /// so their mail was classified as Unknown rather than as a gateway
    /// breaking a signature in transit - which is the difference between a
    /// customer's security product and an impersonator.
    /// </remarks>
    [Theory]
    [InlineData("mx1.iphmx.com", "Cisco IronPort")]
    [InlineData("a.ppe-hosted.com", "Proofpoint Essentials")]
    [InlineData("gw.sonicwall.com", "SonicWall")]
    [InlineData("relay.trendmicro.com", "Trend Micro")]
    public void TheCatalogsGatewaysAreAllKnownHereToo(string envelope, string expected)
    {
        Assert.Equal(expected, FailureClassifier.GatewayName([envelope]));
    }

    /// <summary>
    /// A mail provider is not a gateway, however much of the estate's mail it
    /// carries.
    /// </summary>
    /// <remarks>
    /// The exclusion that used to be a deliberate omission from this class's
    /// own table and is now a consequence of the catalog's SourceKind.
    /// protection.outlook.com is Microsoft's inbound relay and part of the
    /// normal path for every Microsoft 365 tenant in the book; filing it as a
    /// gateway would lift a great deal of ordinary mail out of the compliance
    /// figure.
    /// </remarks>
    [Fact]
    public void AMailProviderIsNotAGateway()
    {
        Assert.Null(FailureClassifier.GatewayName(["acme-com.mail.protection.outlook.com"]));
        Assert.Null(FailureClassifier.GatewayName(["mail-eastus.outbound.protection.outlook.com"]));
    }

    [Fact]
    public void ADomainThatMerelyEndsInTheSameLettersIsNotAGateway()
    {
        // Suffix matching on a label boundary. "notmimecast.com" is somebody
        // else's domain, and naming it Mimecast would be a wrong name on a
        // line an operator is about to act on.
        Assert.Null(FailureClassifier.GatewayName(["notmimecast.com"]));
        Assert.Null(FailureClassifier.GatewayName(["mimecast.com.example.org"]));
    }

    [Fact]
    public void MicrosoftsOwnRelayIsNotTreatedAsAGateway()
    {
        // protection.outlook.com is part of the normal path for every
        // Microsoft 365 tenant in the book. Matching it would file a great
        // deal of ordinary mail as forwarded and quietly lift it out of the
        // compliance figure, which is the opposite of the point.
        Assert.Null(FailureClassifier.GatewayName(["acme-com.mail.protection.outlook.com"]));
    }

    // ---- vendors ---------------------------------------------------------------

    [Fact]
    public void ASourceWhoseSignatureVerifiedIsAVendorRatherThanAForger()
    {
        // A forger has no key anybody's resolver will accept. Whatever else
        // this is, it is a real sender that can be asked to sign as the
        // customer instead.
        Assert.Equal(FailureKind.Vendor, FailureClassifier.Classify(Source(authenticated: true)));
    }

    [Fact]
    public void AVendorHittingSeveralClientsIsStillAVendor()
    {
        // A marketing platform serves every customer in the book and signs as
        // itself for all of them. That is one fact about the platform, not a
        // campaign against the customers.
        var facts = Source(authenticated: true, otherClients: 6);

        Assert.Equal(FailureKind.Vendor, FailureClassifier.Classify(facts));
    }

    // ---- forgery ---------------------------------------------------------------

    [Fact]
    public void AnUnauthenticatedSourceSendingAsSeveralClientsIsForging()
    {
        var facts = Source(otherClients: 6);

        Assert.Equal(FailureKind.Spoofing, FailureClassifier.Classify(facts));
    }

    [Fact]
    public void OneAddressFailingAgainstOneCustomerIsNotCalledForgery()
    {
        // The whole weight of the finding is the cross-client evidence. One
        // address failing for one customer happens every day and proves
        // nothing; called spoofing it would be a wrong accusation printed on
        // the customer's report.
        Assert.Equal(FailureKind.Unknown, FailureClassifier.Classify(Source(otherClients: 0)));
    }

    [Fact]
    public void ASourceThatHasEverPassedForThisDomainIsNotCalledForging()
    {
        // Passing even once is the thing a forger cannot do. A customer's own
        // path that breaks intermittently and also reaches other clients of
        // the same MSP would otherwise be accused of forging them.
        var facts = Source(passing: 3, otherClients: 4);

        Assert.Equal(FailureKind.Unknown, FailureClassifier.Classify(facts));
    }

    // ---- refusing to classify ----------------------------------------------------

    [Fact]
    public void AnAddressNobodyCanNameIsLeftUnknownRatherThanAssumedHostile()
    {
        var kind = FailureClassifier.Classify(Source(envelope: ["some-saas.example"]));

        Assert.Equal(FailureKind.Unknown, kind);
    }

    [Fact]
    public void TheUnknownExplanationDoesNotAccuseAnybody()
    {
        var text = FailureClassifier.Explain(FailureKind.Unknown);

        Assert.Contains("as likely to be a service nobody wrote down", text, StringComparison.Ordinal);
        Assert.DoesNotContain("spoof", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("attack", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EveryKindExplainsItself()
    {
        foreach (var kind in Enum.GetValues<FailureKind>())
        {
            Assert.False(string.IsNullOrWhiteSpace(FailureClassifier.Explain(kind)));
        }
    }

    [Fact]
    public void TheForwardedExplanationSaysNoDnsRecordFixesIt()
    {
        // The sentence that stops somebody weakening a record to move a number
        // that was never about the record.
        Assert.Contains("No DNS record can fix this", FailureClassifier.Explain(FailureKind.Forwarded),
            StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyEnvelopeListNamesNothingRatherThanThrowing()
    {
        Assert.Null(FailureClassifier.GatewayName([]));
        Assert.Null(FailureClassifier.GatewayName(null));
        Assert.Equal(FailureKind.Unknown, FailureClassifier.Classify(Source()));
    }
}
