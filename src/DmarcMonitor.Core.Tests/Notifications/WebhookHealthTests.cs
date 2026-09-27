using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;
using Xunit;

namespace DmarcMonitor.Core.Tests.Notifications;

/// <summary>
/// dmarc health noticing a webhook that has stopped delivering - quietly
/// for one bad night, loudly once findings have piled up for a day and a half.
/// </summary>
public sealed class WebhookHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 27, 9, 10, 0, TimeSpan.Zero);

    private static List<HygieneFinding> Assess(WebhookFacts hook) =>
        HealthCheck.Assess(new HealthFacts { Webhooks = [hook] }, Now).Where(f => f.Record == "webhook").ToList();

    private static WebhookFacts Hook(DateTimeOffset? delivered, DateTimeOffset? failed) =>
        new("local", "https://console.example", Now.AddDays(-30), delivered, failed, "503 Service Unavailable");

    [Fact]
    public void AWorkingWebhookIsNotMentioned()
    {
        Assert.Empty(Assess(Hook(delivered: Now.AddHours(-6), failed: Now.AddDays(-3))));
    }

    [Fact]
    public void OneBadNightIsAWeakness()
    {
        var finding = Assert.Single(Assess(Hook(delivered: Now.AddHours(-30), failed: Now.AddHours(-6))));
        Assert.Equal(HygieneSeverity.Weakness, finding.Severity);
        Assert.Contains("503", finding.Problem, StringComparison.Ordinal);
    }

    /// <summary>Breaking is what reaches the exit code, and so OnFailure= and whoever it tells.</summary>
    [Fact]
    public void ADayAndAHalfWithNothingDeliveredIsBreaking()
    {
        var finding = Assert.Single(Assess(Hook(delivered: Now.AddHours(-40), failed: Now.AddHours(-6))));
        Assert.Equal(HygieneSeverity.Breaking, finding.Severity);
        Assert.Contains("dmarc notify test --org local", finding.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void OneThatHasNeverDeliveredCountsFromWhenItWasSetUp()
    {
        var finding = Assert.Single(Assess(Hook(delivered: null, failed: Now.AddHours(-1))));
        Assert.Equal(HygieneSeverity.Breaking, finding.Severity);
    }
}
