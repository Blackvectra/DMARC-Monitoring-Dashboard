using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using DmarcMonitor.Web.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The separation, end to end: two organisations in one database, and people
/// from each opening the real pages over real HTTP.
///
/// The Core tests prove the queries are scoped. These prove the pages pass
/// the scope in - the failure they exist for is a page that reads first and
/// scopes never, which compiles, renders beautifully, and shows NextLayerSec's
/// clients to NRG.
/// </summary>
public sealed class OrganisationTests : IClassFixture<TwoOrganisationApp>
{
    private readonly TwoOrganisationApp _app;

    public OrganisationTests(TwoOrganisationApp app) => _app = app;

    private HttpClient As(string user, string groups = "", string? org = null)
    {
        var client = _app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        if (groups.Length > 0) { client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups); }
        if (org is not null) { client.DefaultRequestHeaders.Add(TestAuthHandler.OrgHeader, org); }
        return client;
    }

    [Fact]
    public async Task AnNrgEmployeeSeesNrgAndNothingOfNextLayerSec()
    {
        var html = await As("nrg@example.com", TwoOrganisationApp.NrgGroup).GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Corner Post", html, StringComparison.Ordinal);

        // Told which organisation they are in, with nothing to switch to.
        Assert.Contains("NRG Tech Services", html, StringComparison.Ordinal);
        Assert.DoesNotContain("org-switch", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ANextLayerSecEmployeeSeesTheirOwnAndNothingOfNrg()
    {
        var html = await As("nls@example.com", TwoOrganisationApp.NlsGroup).GetStringAsync("/domains");

        Assert.Contains("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheMasterGroupSeesBothAndCanSwitch()
    {
        var html = await As("boss@example.com", TwoOrganisationApp.MasterGroup).GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("cornerpost.example", html, StringComparison.Ordinal);
        Assert.Contains("org-switch", html, StringComparison.Ordinal);
        Assert.Contains("All organisations", html, StringComparison.Ordinal);

        // Across organisations the rows say which is which.
        Assert.Contains(">Organisation<", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMasterNarrowedToOneOrganisationSeesOnlyIt()
    {
        var html = await As("boss@example.com", TwoOrganisationApp.MasterGroup, org: "nextlayersec").GetStringAsync("/");

        Assert.Contains("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/domains")]
    [InlineData("/clients")]
    [InlineData("/fix")]
    [InlineData("/sources")]
    [InlineData("/reports")]
    public async Task SomebodyInNoGroupIsToldSoAndShownNothing(string route)
    {
        var html = await As("stranger@example.com", "33333333-3333-3333-3333-333333333333").GetStringAsync(route);

        Assert.Contains("No organisation", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Acme Corp", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnotherOrganisationsDomainPageConfirmsNothing()
    {
        // The same page a domain nobody has reported on gets, so the URL
        // cannot be used to learn whether NextLayerSec manages a domain.
        var html = await As("nrg@example.com", TwoOrganisationApp.NrgGroup).GetStringAsync("/domains/cornerpost.example");

        Assert.Contains("Nothing stored for", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Corner Post", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Who is reporting", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnotherOrganisationsReportIsNotFound()
    {
        var client = As("nrg@example.com", TwoOrganisationApp.NrgGroup);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/reports/download/acme-corp/2026-08")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/reports/download/corner-post/2026-08")).StatusCode);
    }

    [Fact]
    public async Task SwitchingToAnOrganisationYouCannotSeeIsRefused()
    {
        var response = await As("nrg@example.com", TwoOrganisationApp.NrgGroup).GetAsync("/org/switch?slug=nextlayersec");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ClientsAreListedPerOrganisation()
    {
        var html = await As("nls@example.com", TwoOrganisationApp.NlsGroup).GetStringAsync("/clients");

        Assert.Contains("Corner Post", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Acme Corp", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SettingsShowsOrganisationsAndTheMasterGroupToAMaster()
    {
        var html = await As("boss@example.com", TwoOrganisationApp.MasterGroup).GetStringAsync("/settings");

        Assert.Contains("NextLayerSec", html, StringComparison.Ordinal);
        Assert.Contains(TwoOrganisationApp.MasterGroup, html, StringComparison.Ordinal);
        Assert.Contains("Add an organisation", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEmployeeCannotAdministerOrganisations()
    {
        var html = await As("nrg@example.com", TwoOrganisationApp.NrgGroup).GetStringAsync("/settings");

        Assert.DoesNotContain("Add an organisation", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NobodyIsServedWithoutSigningIn()
    {
        var response = await _app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false }).GetAsync("/");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

/// <summary>
/// The application with Entra sign-in configured and a test scheme standing
/// in for it: whoever the request's headers say, with the groups they say.
/// </summary>
public sealed class TwoOrganisationApp : WebApplicationFactory<Program>
{
    public const string NrgGroup = "11111111-1111-1111-1111-111111111111";
    public const string NlsGroup = "22222222-2222-2222-2222-222222222222";
    public const string MasterGroup = "99999999-9999-9999-9999-999999999999";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-web-{Guid.NewGuid():N}.db");
    private readonly string _secretsDir = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-web-secrets-{Guid.NewGuid():N}");

    public TwoOrganisationApp() => Seed().GetAwaiter().GetResult();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Database:Path", _dbPath);
        builder.UseSetting("Secrets:Directory", _secretsDir);

        // Entra "configured", so the app takes the sign-in path rather than
        // local mode; the test scheme below answers in its place.
        builder.UseSetting("AzureAd:TenantId", "common");
        builder.UseSetting("AzureAd:ClientId", "00000000-0000-0000-0000-000000000001");
        builder.UseSetting("Auth:MasterGroupId", MasterGroup);

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = TestAuthHandler.SchemeName;
                options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
            }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }

    private async Task Seed()
    {
        await new ReportStore(_dbPath).InitialiseAsync(DatabaseSchema.Sql);

        var orgs = new OrganisationStore(_dbPath);
        await orgs.CreateAsync("NextLayerSec", entraGroupId: NlsGroup);

        var nrg = new ReportStore(_dbPath);
        var nls = new ReportStore(_dbPath, "nextlayersec");

        await nrg.SaveAggregateAsync(Report("acme.com", DateTimeOffset.UtcNow.AddDays(-2)), "a", null);
        await nrg.SaveAggregateAsync(Report("acme.com", new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero)), "b", null);
        await nls.SaveAggregateAsync(Report("cornerpost.example", DateTimeOffset.UtcNow.AddDays(-2)), "c", null);
        await nls.SaveAggregateAsync(Report("cornerpost.example", new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero)), "d", null);

        await nrg.AssignDomainAsync("acme.com", (await nrg.CreateClientAsync("Acme Corp"))!);
        await nls.AssignDomainAsync("cornerpost.example", (await nls.CreateClientAsync("Corner Post"))!);

        // The built-in organisation, named and given its group, the way an
        // operator would from the settings page.
        await orgs.RenameAsync(ReportStore.DefaultTenantSlug, "NRG Tech Services");
        await orgs.SetGroupAsync(ReportStore.DefaultTenantSlug, NrgGroup);
    }

    private static AggregateReport Report(string domain, DateTimeOffset begin)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>90</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>10</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>fail</result></dkim><spf><domain>{domain}</domain><result>fail</result></spf></auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        return parsed.Report!;
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

/// <summary>
/// Signs a request in as whoever its headers name. No headers, no user, and
/// the fallback policy answers 401 the way a real challenge would.
/// </summary>
internal sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";
    public const string UserHeader = "X-Test-User";
    public const string GroupsHeader = "X-Test-Groups";
    public const string OrgHeader = "X-Test-Org";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(UserHeader, out var user) || string.IsNullOrEmpty(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.ToString()),
            new(ClaimTypes.NameIdentifier, user.ToString()),
        };

        foreach (var group in Request.Headers[GroupsHeader].ToString()
                     .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            claims.Add(new Claim("groups", group));
        }

        if (Request.Headers.TryGetValue(OrgHeader, out var org) && !string.IsNullOrEmpty(org))
        {
            claims.Add(new Claim(OrgContext.ChoiceClaim, org.ToString()));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        return Task.CompletedTask;
    }
}
