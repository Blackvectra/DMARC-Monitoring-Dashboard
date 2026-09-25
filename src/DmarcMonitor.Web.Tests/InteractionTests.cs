using System.Reflection;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Web.Components.Pages;
using DmarcMonitor.Web.Data;
using DnsClient;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The Reports page after something has gone wrong, which is when a person
/// is still looking at it.
/// </summary>
public sealed class ReportsPageTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public ReportsPageTests(SeededApp app) => _app = app;

    /// <summary>A month the picker offers whatever today's date, so the picker can always be found.</summary>
    private static string Offered => ReportUiService.RecentMonths()[0].Value;

    [Fact]
    public async Task AMonthThatWillNotBuildLeavesThePickersAndTheNextChoiceWorks()
    {
        await using var page = await LivePage.OpenAsync<Reports>(_app);

        // The page opens on the newest month with data, and previews it.
        var month = await page.ValueOfAsync(Offered);
        Assert.NotNull(month);
        Assert.Contains("figure-n", await page.HtmlAsync(), StringComparison.Ordinal);

        // A month no calendar holds: what the select sends when its options
        // have been edited in the browser, and a failure that needs no broken
        // database to produce.
        await page.ChooseAsync(Offered, "0001-01");

        var failed = await page.HtmlAsync();
        Assert.Contains("Could not build that month", failed, StringComparison.Ordinal);

        // A failure is not an empty month. "Nothing stored" would be the page
        // claiming to know something it does not.
        Assert.DoesNotContain("Nothing stored for that month", failed, StringComparison.Ordinal);

        // The pickers are still there, and a month that builds is built. This
        // is the step that could not be taken: the failure replaced the whole
        // page, pickers included, and nothing ever cleared it.
        await page.ChooseAsync(Offered, month!);

        var recovered = await page.HtmlAsync();
        Assert.DoesNotContain("Could not build that month", recovered, StringComparison.Ordinal);
        Assert.Contains("figure-n", recovered, StringComparison.Ordinal);
    }
}

/// <summary>
/// The Fix page when one domain is read again and the reading fails.
/// </summary>
public sealed class FixPageTests : IClassFixture<OfflineApp>
{
    private readonly OfflineApp _app;

    public FixPageTests(OfflineApp app) => _app = app;

    [Fact]
    public async Task AFailedCheckAgainKeepsThePageAndSaysSoBesideTheDomain()
    {
        await using var page = await LivePage.OpenAsync<Fix>(_app);
        await page.WaitForAsync(
            html => html.Contains("Check again", StringComparison.Ordinal)
                && !html.Contains("Checking what it publishes", StringComparison.Ordinal),
            "every domain to have been read once");

        _app.Secrets.Broken = true;
        try
        {
            await page.ClickAsync("Check again", inSectionWith: "acme.com");
        }
        finally
        {
            _app.Secrets.Broken = false;
        }

        var html = await page.HtmlAsync();

        // Not the page-wide failure, which replaced every domain and the
        // change history with one line until the page was reloaded.
        Assert.DoesNotContain("Could not plan", html, StringComparison.Ordinal);
        Assert.Contains("/domains/acme.com", html, StringComparison.Ordinal);
        Assert.Contains("/domains/signed.example", html, StringComparison.Ordinal);
        Assert.Contains("What has been changed", html, StringComparison.Ordinal);

        // What went wrong is said, beside the domain that was asked about.
        Assert.Contains(BreakableSecrets.Failure, html, StringComparison.Ordinal);

        // And a check that then works takes the complaint away with it.
        await page.ClickAsync("Check again", inSectionWith: "acme.com");
        Assert.DoesNotContain(BreakableSecrets.Failure, await page.HtmlAsync(), StringComparison.Ordinal);
    }
}

/// <summary>
/// The seeded install cut off from the network, with a secret store a test
/// can break.
/// </summary>
/// <remarks>
/// The Fix page reads DNS for every domain once it is on screen. Against the
/// real resolver that would be a test of the network, taking as long as the
/// timeouts; here every lookup fails at once, the way one that could not be
/// made does, and the page says so for each domain.
/// </remarks>
public sealed class OfflineApp : SeededApp
{
    public BreakableSecrets Secrets { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton(new DnsLookup(NoNetwork.Resolver()));
            services.AddSingleton<ISecretStore>(Secrets);
        });
    }
}

/// <summary>A resolver with nothing behind it: every question fails the way an unanswered one does.</summary>
public class NoNetwork : DispatchProxy
{
    public static ILookupClient Resolver() => Create<ILookupClient, NoNetwork>();

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
        throw new DnsResponseException("There is no network in this test.");
}

/// <summary>
/// Provider tokens, readable until a test says otherwise.
/// </summary>
/// <remarks>
/// A store that stops answering is an ordinary way for reading one domain
/// again to fail: the key file's permissions change, or the key is replaced
/// under the running service.
/// </remarks>
public sealed class BreakableSecrets : ISecretStore
{
    public const string Failure = "Access to the secret store was denied.";

    private volatile bool _broken;

    public bool Broken
    {
        get => _broken;
        set => _broken = value;
    }

    public bool IsAvailable => true;

    public string Description => "a store a test can break";

    public Task SetAsync(string credentialRef, string secret, CancellationToken ct = default) => Task.CompletedTask;

    public Task<string?> GetAsync(string credentialRef, CancellationToken ct = default) =>
        _broken
            ? Task.FromException<string?>(new UnauthorizedAccessException(Failure))
            : Task.FromResult<string?>(SeededApp.ProviderToken);

    public Task RemoveAsync(string credentialRef, CancellationToken ct = default) => Task.CompletedTask;
}
