using System.Net;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Hosting;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Every page, loaded for real against a database with data in it.
///
/// The logic behind these pages is covered by six hundred tests in Core. None
/// of them would notice a renamed property in a .razor file, a broken @bind,
/// or a page that throws on an empty database: all three compile, and all
/// three pass the entire suite. Every such fault found so far was found by a
/// person driving the app by hand, which does not survive into next week.
///
/// These run the real application in process, over real HTTP, through the
/// real authentication pipeline. They assert on one sentence per page rather
/// than on markup, so they fail when a page breaks and stay quiet when it is
/// restyled.
/// </summary>
public sealed class PageTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public PageTests(SeededApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        // Local trial mode redirects to its own sign-in and sets a cookie.
        // Following that is what a browser does, and not following it turns
        // every one of these into a test of the redirect.
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    public static TheoryData<string> EveryRoute => new()
    {
        "/",
        "/domains",
        "/domains/acme.com",
        "/fix",
        "/clients",
        "/import",
        "/sources",
        "/reports",
        "/settings",
        "/updates",
    };

    [Theory]
    [MemberData(nameof(EveryRoute))]
    public async Task EveryRouteInTheSidebarLoads(string route)
    {
        // A sidebar link that 404s is what somebody meets first. Three of
        // these did, for most of a day.
        var response = await Client().GetAsync(route);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(EveryRoute))]
    public async Task NoPageRendersAnUnhandledError(string route)
    {
        // A Blazor component that throws during render still returns 200 with
        // an error boundary in the body, so the status code alone proves
        // nothing.
        var html = await Client().GetStringAsync(route);

        Assert.DoesNotContain("An unhandled error has occurred", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Unhandled exception", html, StringComparison.OrdinalIgnoreCase);
    }

    // ---- what each page is for ----------------------------------------------

    [Fact]
    public async Task TriageNamesTheDomainAndWhatItNeeds()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("refused outright", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TriageDoesNotGoQuietAboutMailBeingRefused()
    {
        // The seeded domain is at p=reject on 96%, above the healthy
        // threshold, with 40 messages being refused. That row was empty for
        // most of a day because the percentage looked fine.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("40 message(s)", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageOpensFromItsName()
    {
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("Who is reporting", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageSaysWhenAValidSignatureIsBeingThrownAwayForTheWrongDomain()
    {
        // The whole point of the section. A report row reading "dkim=pass"
        // beside "dmarc=fail" looks like the product is wrong to anybody who
        // has already set DKIM up with the vendor, and they stop looking.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("signing correctly for the wrong domain", html, StringComparison.Ordinal);
        Assert.Contains("d=training.vendor.example", html, StringComparison.Ordinal);

        // And the distinction itself, not just the label.
        Assert.Contains("the signing domain to match", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageNamesTheSameVendorsWorkingPathAsProofItCanBeDone()
    {
        // Both hosts carry the same envelope domain, and one of them already
        // signs as the customer. That fact is what a vendor cannot argue with.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("23.21.109.197", html, StringComparison.Ordinal);
        Assert.Contains("the capability exists on", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageOffersNoVendorProofForADomainThatHasNone()
    {
        // acme.com has no third party signing for it at all, so there is no
        // working path to point at. Claiming one would be an invention.
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.DoesNotContain("the capability exists on", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainWhoseMailIsMerelyUnsignedIsNotAccusedOfMisalignment()
    {
        // acme.com's failures have no valid signature at all, which is a
        // different fault with a different fix. Offering alignment advice
        // there sends somebody to a vendor setting that is not the problem.
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.DoesNotContain("signing correctly for the wrong domain", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainNobodyHasReportedOnIsOnboardingRatherThanAnError()
    {
        var response = await Client().GetAsync("/domains/never-seen.example");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Nothing stored for", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClientsListsTheClientAndSaysWhichMessageCountItIs()
    {
        // Two pages showed "Messages" meaning different windows.
        var html = await Client().GetStringAsync("/clients");

        Assert.Contains("Acme Corp", html, StringComparison.Ordinal);
        Assert.Contains("all time", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReportsWarnsThatItWouldSignWithThePlaceholder()
    {
        // Reporting:ProviderName is unset in the test host, as it is in a
        // fresh install. This page is where a document is opened and sent.
        var html = await Client().GetStringAsync("/reports");

        Assert.Contains("Reports will be signed", html, StringComparison.Ordinal);
        Assert.Contains("Acme Corp", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/settings")]
    [InlineData("/fix")]
    [InlineData("/")]
    public async Task NoPageEverShowsAProviderToken(string route)
    {
        // The settings page lists the provider and its credential reference.
        // The reference is fine to show; the token behind it is not, on this
        // page or any other, in a screenshot or a support ticket.
        var html = await Client().GetStringAsync(route);

        Assert.DoesNotContain(SeededApp.ProviderToken, html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SettingsNamesTheProviderAndWhereSecretsLive()
    {
        var html = await Client().GetStringAsync("/settings");

        Assert.Contains("cloudflare", html, StringComparison.Ordinal);
        Assert.Contains("zone-acme", html, StringComparison.Ordinal);
        Assert.Contains("dmarc.local.cloudflare.", html, StringComparison.Ordinal);
        Assert.Contains("never", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FixSaysWhatItIsForBeforeAnythingIsRead()
    {
        // DNS is read after first render, so the static page is what a
        // request sees. It has to say what will happen, not sit blank.
        var html = await Client().GetStringAsync("/fix");

        Assert.Contains("what we did", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReportDownloadsAsAWholeDocument()
    {
        var response = await Client().GetAsync("/reports/download/acme-corp/2026-08");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("Email Protection Report", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReportForAClientThatDoesNotExistIsNotFound()
    {
        var response = await Client().GetAsync("/reports/download/no-such-client/2026-08");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ABadMonthIsRefusedRatherThanGuessedAt()
    {
        var response = await Client().GetAsync("/reports/download/acme-corp/August");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SettingsSaysWhetherSignInIsOn()
    {
        // The question an operator cannot otherwise answer.
        var html = await Client().GetStringAsync("/settings");

        Assert.Contains("local trial mode", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SettingsNeverPrintsASecret()
    {
        // A client secret on a settings page is a secret in a screenshot in a
        // support ticket.
        var html = await Client().GetStringAsync("/settings");

        Assert.DoesNotContain("ClientSecret", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(SeededApp.ProviderToken, html, StringComparison.Ordinal);

        // The page does take a token in, once, through a password field, so
        // what is typed is not on the screen either.
        Assert.Contains("type=\"password\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SourcesSeparatesARelayFromAnImpersonator()
    {
        var html = await Client().GetStringAsync("/sources");

        // The relay sends legitimately for this domain as well as failing, so
        // it must not be described as somebody sending as the client.
        Assert.DoesNotContain("Authenticated nothing, against", html, StringComparison.Ordinal);
    }
}

/// <summary>
/// The application, started in process against a database with known data.
///
/// One database for the whole class: these are read-only pages, and building
/// it per test would make the suite slower than the thing it is testing.
/// </summary>
public sealed class SeededApp : WebApplicationFactory<Program>
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-pages-{Guid.NewGuid():N}.db");
    private readonly string _secretsDir =
        Path.Combine(Path.GetTempPath(), $"dmarc-pages-secrets-{Guid.NewGuid():N}");

    /// <summary>The token stored for the seeded provider. Must never appear in any page.</summary>
    public const string ProviderToken = "cf-token-KEEP-OUT-OF-PAGES-9f8e7d";

    public SeededApp() => Seed().GetAwaiter().GetResult();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Configuration rather than swapping the registration. Program
        // resolves the path once at startup and hands it to several services
        // as a plain string, so replacing DatabaseInfo afterwards moves only
        // one of them - the pages then read a seeded database while the
        // triage list reads the default, and everything renders an empty
        // state that looks like a passing test. Going in through
        // configuration is also what a real deployment does.
        builder.UseSetting("Database:Path", _dbPath);
        builder.UseSetting("Secrets:Directory", _secretsDir);
    }

    private async Task Seed()
    {
        var store = new ReportStore(_dbPath);
        await store.InitialiseAsync(DatabaseSchema.Sql);

        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var august = new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero);

        // Recent, so the triage window sees it: enforcing, above the healthy
        // threshold, and still refusing 40 messages. That combination was
        // silent on the triage page and is the reason these tests exist.
        await StoreAsync(store, begin, 960, 40);

        // And a month with data in it, so a report can be generated.
        await StoreAsync(store, august, 200, 10);

        // A second domain carrying the shape that reads as a contradiction: a
        // vendor whose DKIM signature verifies over its own domain, beside the
        // same vendor's other host signing as the customer correctly. Kept off
        // acme.com so the figures the other tests assert on do not move.
        await StoreUnalignedAsync(store, begin);

        var slug = await store.CreateClientAsync("Acme Corp");
        await store.AssignDomainAsync("acme.com", slug!);
        await store.AssignDomainAsync("signed.example", slug!);

        // A provider with a real-looking token, stored the way the settings
        // page stores one, so the pages can be checked for leaking it.
        var configs = new DnsProviderConfigs(_dbPath, new LocalSecretStore(_secretsDir));
        await configs.SetAsync(slug!, null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "zone-acme" }, ProviderToken);
    }

    private static async Task StoreAsync(ReportStore store, DateTimeOffset begin, int passing, int failing)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.25</source_ip><count>{passing}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><selector>selector1</selector><result>pass</result></dkim>
                  <spf><domain>acme.com</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>192.0.2.25</source_ip><count>{failing}</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><selector>selector1</selector><result>fail</result></dkim>
                  <spf><domain>acme.com</domain><result>fail</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    /// <summary>The valid-signature-wrong-domain case, published at p=reject.</summary>
    private static async Task StoreUnalignedAsync(ReportStore store, DateTimeOffset begin)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>signed.example</domain><p>reject</p><pct>100</pct>
                <adkim>s</adkim><aspf>s</aspf></policy_published>
              <record>
                <row>
                  <source_ip>23.21.109.197</source_ip><count>14</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>signed.example</domain><selector>s1</selector><result>pass</result></dkim>
                  <spf><domain>psm.vendor.example</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>147.160.167.15</source_ip><count>289</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>training.vendor.example</domain><selector>s2</selector><result>pass</result></dkim>
                  <spf><domain>psm.vendor.example</domain><result>pass</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) { return; }

        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
        try { Directory.Delete(_secretsDir, recursive: true); } catch (IOException) { }
    }
}
