using Microsoft.AspNetCore.Mvc.Testing;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The by-domain page: one card per domain saying who sent its mail and who
/// failed, so the whole book can be read without opening each domain.
/// </summary>
public sealed class BriefingPageTests : IClassFixture<SendersApp>
{
    private readonly SendersApp _app;

    public BriefingPageTests(SendersApp app) => _app = app;

    private async Task<string> PageAsync() =>
        await _app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
                  .GetStringAsync("/briefing");

    /// <summary>The card for <paramref name="domain"/>, up to the next one.</summary>
    private static string Card(string html, string domain) =>
        html.Split("briefing-card").Skip(1).Single(c => c.Contains($"data-domain=\"{domain}\"", StringComparison.Ordinal));

    [Fact]
    public async Task EachDomainWithMailHasItsOwnCard()
    {
        var html = await PageAsync();

        foreach (var domain in new[] { "alpha.example", "beta.example", "gamma.example" })
        {
            Assert.Contains($"data-domain=\"{domain}\"", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ACardNamesItsFailingSendersWithTheirCounts()
    {
        var card = Card(await PageAsync(), "alpha.example");

        // Unauthenticated and named by nothing: sending as the domain without
        // authenticating, by the name it displays as and its count.
        Assert.Contains("without authenticating", card, StringComparison.Ordinal);
        Assert.Contains("203.0.113.50 3", card, StringComparison.Ordinal);
        Assert.Contains("p=none", card, StringComparison.Ordinal);
        Assert.Contains("href=\"domains/alpha.example\"", card, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheMenuLinksToIt()
    {
        var html = await PageAsync();

        Assert.Contains("href=\"briefing\"", html, StringComparison.Ordinal);
    }
}
