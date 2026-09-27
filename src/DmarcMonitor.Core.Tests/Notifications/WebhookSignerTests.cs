using DmarcMonitor.Core.Notifications;
using Xunit;

namespace DmarcMonitor.Core.Tests.Notifications;

/// <summary>
/// The signature a receiver checks before believing anything an event says.
/// </summary>
public sealed class WebhookSignerTests
{
    private const string Secret = "contract-test-secret-0123456789abcdef";
    private const long Timestamp = 1790000000;
    private const string Body = """{"schema":"dmarc-monitor.event.v1","id":"4f0c2a52-9d63-4b8e-a0c1-2b7e6f1d9a10","type":"ping"}""";

    /// <summary>
    /// Computed independently (Python's hmac module), and asserted by the
    /// receiver's own tests too. If this changes, every receiver already
    /// deployed starts refusing everything, so it is pinned rather than
    /// round-tripped: a round trip passes whatever the scheme becomes.
    /// </summary>
    private const string Expected = "v1=ea9dc5229cf57493b6afd4de88a5b1b0f99901b6427f97ed78cf64e5da36f721";

    [Fact]
    public void MatchesTheSignatureEveryReceiverChecksAgainst()
    {
        Assert.Equal(Expected, WebhookSigner.Sign(Secret, Timestamp, Body));
    }

    [Fact]
    public void AcceptsItsOwnSignature()
    {
        Assert.True(WebhookSigner.Verify(Secret, Timestamp, Body, Expected));
    }

    [Fact]
    public void RefusesAnAlteredBody()
    {
        Assert.False(WebhookSigner.Verify(Secret, Timestamp, Body.Replace("ping", "dns.drift", StringComparison.Ordinal), Expected));
    }

    /// <summary>The timestamp is signed, so a captured request cannot be replayed with a fresh one.</summary>
    [Fact]
    public void RefusesAMovedTimestamp()
    {
        Assert.False(WebhookSigner.Verify(Secret, Timestamp + 1, Body, Expected));
    }

    [Fact]
    public void RefusesAnotherSecret()
    {
        Assert.False(WebhookSigner.Verify(Secret + "x", Timestamp, Body, Expected));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("v1=")]
    [InlineData("ea9dc5229cf57493b6afd4de88a5b1b0f99901b6427f97ed78cf64e5da36f721")]
    public void RefusesWhatIsNotASignature(string? given)
    {
        Assert.False(WebhookSigner.Verify(Secret, Timestamp, Body, given));
    }
}
