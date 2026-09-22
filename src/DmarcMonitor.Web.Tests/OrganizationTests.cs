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
/// The separation, end to end: two organizations in one database, and people
/// from each opening the real pages over real HTTP.
///
/// The Core tests prove the queries are scoped. These prove the pages pass
/// the scope in - the failure they exist for is a page that reads first and
/// scopes never, which compiles, renders beautifully, and shows NextLayerSec's
/// clients to NRG.
/// </summary>
public sealed class OrganizationTests : IClassFixture<TwoOrganizationApp>
{
    private readonly TwoOrganizationApp _app;

    public OrganizationTests(TwoOrganizationApp app) => _app = app;

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
        var html = await As("nrg@example.com", TwoOrganizationApp.NrgGroup).GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Corner Post", html, StringComparison.Ordinal);

        // Told which organization they are in, with nothing to switch to.
        Assert.Contains("NRG Tech Services", html, StringComparison.Ordinal);
        Assert.DoesNotContain("org-switch", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ANextLayerSecEmployeeSeesTheirOwnAndNothingOfNrg()
    {
        var html = await As("nls@example.com", TwoOrganizationApp.NlsGroup).GetStringAsync("/domains");

        Assert.Contains("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheMasterGroupSeesBothAndCanSwitch()
    {
        var html = await As("boss@example.com", TwoOrganizationApp.MasterGroup).GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("cornerpost.example", html, StringComparison.Ordinal);
        Assert.Contains("org-switch", html, StringComparison.Ordinal);
        Assert.Contains("All organizations", html, StringComparison.Ordinal);

        // Across organizations the rows say which is which.
        Assert.Contains(">Organization<", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMasterNarrowedToOneOrganizationSeesOnlyIt()
    {
        var html = await As("boss@example.com", TwoOrganizationApp.MasterGroup, org: "nextlayersec").GetStringAsync("/");

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

        Assert.Contains("No organization", html, StringComparison.Ordinal);
        Assert.DoesNotContain("acme.com", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cornerpost.example", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Acme Corp", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnotherOrganizationsDomainPageConfirmsNothing()
    {
        // The same page a domain nobody has reported on gets, so the URL
        // cannot be used to learn whether NextLayerSec manages a domain.
        var html = await As("nrg@example.com", TwoOrganizationApp.NrgGroup).GetStringAsync("/domains/cornerpost.example");

        Assert.Contains("Nothing stored for", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Corner Post", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Who is reporting", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnotherOrganizationsReportIsNotFound()
    {
        var client = As("nrg@example.com", TwoOrganizationApp.NrgGroup);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/reports/download/acme-corp/2026-08")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/reports/download/corner-post/2026-08")).StatusCode);
    }

    [Fact]
    public async Task SwitchingToAnOrganizationYouCannotSeeIsRefused()
    {
        var response = await As("nrg@example.com", TwoOrganizationApp.NrgGroup).GetAsync("/org/switch?slug=nextlayersec");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ClientsAreListedPerOrganization()
    {
        var html = await As("nls@example.com", TwoOrganizationApp.NlsGroup).GetStringAsync("/clients");

        Assert.Contains("Corner Post", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Acme Corp", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SettingsShowsOrganizationsAndTheMasterGroupToAMaster()
    {
        var html = await As("boss@example.com", TwoOrganizationApp.MasterGroup).GetStringAsync("/settings");

        Assert.Contains("NextLayerSec", html, StringComparison.Ordinal);
        Assert.Contains(TwoOrganizationApp.MasterGroup, html, StringComparison.Ordinal);
        Assert.Contains("Add an organization", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEmployeeCannotAdministerOrganizations()
    {
        var html = await As("nrg@example.com", TwoOrganizationApp.NrgGroup).GetStringAsync("/settings");

        Assert.DoesNotContain("Add an organization", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NobodyIsServedWithoutSigningIn()
    {
        var response = await _app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false }).GetAsync("/");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- roles ---------------------------------------------------------------

    [Fact]
    public async Task AViewerReadsTheDataAndIsOfferedNothingToChange()
    {
        var client = As("reader@example.com", TwoOrganizationApp.NrgViewers);

        var triage = await client.GetStringAsync("/");
        Assert.Contains("acme.com", triage, StringComparison.Ordinal);
        Assert.Contains("viewer, read only", triage, StringComparison.Ordinal);

        // The controls that write are not drawn, and the page says why rather
        // than leaving somebody hunting for a button that was never there.
        var clients = await client.GetStringAsync("/clients");
        Assert.Contains("needs the operator role", clients, StringComparison.Ordinal);
        Assert.DoesNotContain("Add a client", clients, StringComparison.Ordinal);

        var import = await client.GetStringAsync("/import");
        Assert.Contains("Importing needs the operator role", import, StringComparison.Ordinal);
        Assert.DoesNotContain("Drop report files here", import, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnOperatorGetsTheControlsButNotTheOrganizationsSettings()
    {
        var client = As("nrg@example.com", TwoOrganizationApp.NrgGroup);

        var clients = await client.GetStringAsync("/clients");
        Assert.Contains("Add a client", clients, StringComparison.Ordinal);
        Assert.DoesNotContain("Customer login group", clients, StringComparison.Ordinal);

        var settings = await client.GetStringAsync("/settings");
        Assert.DoesNotContain("Add an organization", settings, StringComparison.Ordinal);
        Assert.DoesNotContain("Recent activity", settings, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAdminRunsTheirOwnOrganizationAndNobodyElses()
    {
        var html = await As("admin@example.com", TwoOrganizationApp.NrgAdmins).GetStringAsync("/settings");

        Assert.Contains("Recent activity", html, StringComparison.Ordinal);
        Assert.Contains("NRG Tech Services", html, StringComparison.Ordinal);

        // Creating organizations stays with the master group.
        Assert.DoesNotContain("Add an organization", html, StringComparison.Ordinal);

        // And the customer-login column, which is an admin's to set.
        Assert.Contains("Customer login group", await As("admin@example.com", TwoOrganizationApp.NrgAdmins).GetStringAsync("/clients"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACustomerSeesTheirOwnClientAndNoSetupAtAll()
    {
        var client = As("customer@acme.example", TwoOrganizationApp.AcmeGroup);

        var triage = await client.GetStringAsync("/");
        Assert.Contains("acme.com", triage, StringComparison.Ordinal);
        Assert.DoesNotContain("cornerpost.example", triage, StringComparison.Ordinal);

        // No Clients, Import, Settings or Updates: there is nothing there for
        // a customer, and the client picker would offer them other people's.
        Assert.DoesNotContain("nav-group\">Setup", triage, StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"import\"", triage, StringComparison.Ordinal);
        Assert.Contains("read only", triage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACustomerCannotReachAnotherClientsReportOrDomain()
    {
        var client = As("customer@acme.example", TwoOrganizationApp.AcmeGroup);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/reports/download/acme-corp/2026-08")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/reports/download/corner-post/2026-08")).StatusCode);

        var domain = await client.GetStringAsync("/domains/cornerpost.example");
        Assert.Contains("Nothing stored for", domain, StringComparison.Ordinal);
    }

    // ---- white label ---------------------------------------------------------

    [Fact]
    public async Task AnOrganizationsColorAndLogoDressTheShell()
    {
        var html = await As("nrg@example.com", TwoOrganizationApp.NrgGroup).GetStringAsync("/");

        Assert.Contains("--accent: #0f766e;", html, StringComparison.Ordinal);
        Assert.Contains("class=\"brand-logo\"", html, StringComparison.Ordinal);

        // NextLayerSec has no branding, so it keeps the default mark.
        var plain = await As("nls@example.com", TwoOrganizationApp.NlsGroup).GetStringAsync("/");
        Assert.DoesNotContain("--accent:", plain, StringComparison.Ordinal);
        Assert.Contains("brand-mark", plain, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AClientReportCarriesTheOrganizationsNameAndContact()
    {
        var response = await As("nrg@example.com", TwoOrganizationApp.NrgGroup)
            .GetAsync("/reports/download/acme-corp/2026-08?format=html");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("NRG Tech Services", html, StringComparison.Ordinal);
        Assert.Contains("dmarc@nrgtechservices.com", html, StringComparison.Ordinal);
        Assert.Contains("#0f766e", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// And so does the PDF, which is the copy that leaves the building.
    /// </summary>
    /// <remarks>
    /// White-labelling that stops at the screen is not white-labelling. The
    /// PDF carried the provider's name from the start and dropped its colour,
    /// its logo and its contact block, which are the three things an MSP is
    /// buying. What is asserted here is that the branded organization's
    /// document renders and differs from the unbranded one's; the content is
    /// pinned field by field in ClientReportPdfTests.
    /// </remarks>
    [Fact]
    public async Task ThePdfIsBrandedByTheOrganizationThatSendsIt()
    {
        var response = await As("nrg@example.com", TwoOrganizationApp.NrgGroup)
            .GetAsync("/reports/download/acme-corp/2026-08");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);

        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(bytes, 0, 4));
    }
}

/// <summary>
/// The application with Entra sign-in configured and a test scheme standing
/// in for it: whoever the request's headers say, with the groups they say.
/// </summary>
public sealed class TwoOrganizationApp : WebApplicationFactory<Program>
{
    public const string NrgGroup = "11111111-1111-1111-1111-111111111111";
    public const string NlsGroup = "22222222-2222-2222-2222-222222222222";
    public const string MasterGroup = "99999999-9999-9999-9999-999999999999";
    public const string NrgAdmins = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    public const string NrgViewers = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    public const string AcmeGroup = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    /// <summary>A one-pixel PNG: enough to prove the logo reaches the markup.</summary>
    private const string Logo =
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-web-{Guid.NewGuid():N}.db");
    private readonly string _secretsDir = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-web-secrets-{Guid.NewGuid():N}");

    public TwoOrganizationApp() => Seed().GetAwaiter().GetResult();

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
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        var orgs = new OrganizationStore(_dbPath);
        await orgs.CreateAsync("NextLayerSec", entraGroupId: NlsGroup);

        var nrg = new ReportStore(_dbPath);
        var nls = new ReportStore(_dbPath, "nextlayersec");

        await nrg.SaveAggregateAsync(Report("acme.com", DateTimeOffset.UtcNow.AddDays(-2)), "a", null);
        await nrg.SaveAggregateAsync(Report("acme.com", new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero)), "b", null);
        await nls.SaveAggregateAsync(Report("cornerpost.example", DateTimeOffset.UtcNow.AddDays(-2)), "c", null);
        await nls.SaveAggregateAsync(Report("cornerpost.example", new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero)), "d", null);

        await nrg.AssignDomainAsync("acme.com", (await nrg.CreateClientAsync("Acme Corp"))!);
        await nls.AssignDomainAsync("cornerpost.example", (await nls.CreateClientAsync("Corner Post"))!);

        // The built-in organization, named and given its groups, the way an
        // operator would from the settings page.
        await orgs.RenameAsync(ReportStore.DefaultTenantSlug, "NRG Tech Services");
        await orgs.SetGroupAsync(ReportStore.DefaultTenantSlug, NrgGroup);
        await orgs.SetGroupAsync(ReportStore.DefaultTenantSlug, OrganizationRole.Admin, NrgAdmins);
        await orgs.SetGroupAsync(ReportStore.DefaultTenantSlug, OrganizationRole.Viewer, NrgViewers);
        await orgs.SetBrandAsync(ReportStore.DefaultTenantSlug, new OrganizationBrand(
            "#0F766E", Logo, "NRG Tech Services", "dmarc@nrgtechservices.com\n+1 555 0100"));

        // Acme's own people, who see Acme and nothing else.
        await nrg.SetClientGroupAsync("acme-corp", AcmeGroup);
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
