using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Web;
using DmarcMonitor.Web.Auth;
using DmarcMonitor.Web.Components;
using DmarcMonitor.Web.Data;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// On Windows the app runs as a service (deploy/bootstrap.ps1 installs it as
// one). Without this the process never tells the Service Control Manager it
// has started, and the SCM kills it after thirty seconds as "failed to
// respond" - a service that runs perfectly for half a minute and then dies,
// which reads as a crash. On Linux, or when started from a shell anywhere,
// this is a no-op.
builder.Host.UseWindowsService();

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.AddAppAuthentication();

// Whatever holds the TLS certificate - Caddy, nginx, IIS, a load balancer -
// is in front of this, and without being told so the app sees every request
// as plain HTTP from 127.0.0.1. See ProxySetup for what that breaks.
builder.AddProxySupport();

// One database path, resolved once to an absolute path, so a misconfiguration
// is a startup problem rather than a page that renders empty and looks like no
// data. Absolute matters for what the pages say too: "no database at dmarc.db"
// sends an operator looking in the wrong directory, because a relative path is
// resolved against wherever the service happened to be started.
var dbPath = Path.GetFullPath(builder.Configuration["Database:Path"] ?? "dmarc.db");
builder.Services.AddSingleton(new DatabaseInfo(dbPath));

// The keys that sign the sign-in cookie and the antiforgery token, kept beside
// the database rather than where ASP.NET Core puts them when nobody says -
// under the account's home directory. A service unit that hides the home
// directory (ProtectHome=true, which is the right setting for a service) then
// gets keys that live in memory only, and everybody is signed out every time
// the service restarts. That reads as a flaky login, not as a permissions
// problem, and it is why the unit file used to carry a comment explaining
// why it could not protect the home directory. Now the keys are wherever the
// data is, backed up with it, and the unit can.
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Path.GetDirectoryName(dbPath) ?? ".", "keys")));
builder.Services.AddSingleton<ReportStoreConnection>();
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Rollout.TriageService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Reporting.TimeSeriesService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Intelligence.CorrelationService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Domains.DomainDetailService(dbPath));

// The one write path a page has. See OnboardingService for why it is an
// exception to the read-only rule rather than a loosening of it.
builder.Services.AddScoped<OnboardingService>();

// Organizations: the layer above clients, and who may see which. Every page
// asks OrgContext for its scope before it asks the database for anything.
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Tenancy.OrganizationStore(dbPath));
builder.Services.AddScoped<OrgContext>();

// Who did what. Written by the pages that change setup, read on Settings.
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Tenancy.AuditLog(dbPath));
builder.Services.AddScoped<ImportUiService>();
builder.Services.AddScoped<ReportUiService>();

// Shared, because it caches: a page opened twice in a minute should not ask
// the resolver twice. Reading DNS is also the only thing here that reaches
// outside the machine, so it is the one service whose slowness can be seen.
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.DnsLookup());

// The write path that reaches outside the machine: it changes a customer's
// DNS. Provider tokens live in the secret store, never in the database, and
// the store's location is configurable so a service account can keep its own.
var secretsDir = builder.Configuration["Secrets:Directory"];
builder.Services.AddSingleton<DmarcMonitor.Core.Remediation.ISecretStore>(_ =>
    new DmarcMonitor.Core.Remediation.LocalSecretStore(string.IsNullOrWhiteSpace(secretsDir) ? null : Path.GetFullPath(secretsDir)));
builder.Services.AddScoped(sp => new DmarcMonitor.Core.Remediation.DnsProviderConfigs(
    dbPath, sp.GetRequiredService<DmarcMonitor.Core.Remediation.ISecretStore>()));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Remediation.RemediationService(dbPath));
builder.Services.AddScoped<RemediationUiService>();
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.MtaStsStore(dbPath));
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.MtaStsFetcher());
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Updates.ReleaseChannel());

// Where the app writes down a version it would like installed. It writes a
// version and nothing else; a separate unit with the privileges to do the
// work checks it and acts. See UpdateSpool for why the app is not allowed to
// install anything itself.
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Updates.UpdateSpool(
    Path.Combine(Path.GetDirectoryName(dbPath) ?? ".", "updates")));

var app = builder.Build();

// First, so everything after it sees the caller's real address and scheme.
app.UseProxyHeaders();

// Before anything that can write a response, including the error handler and
// the static files below, so every byte this app sends carries them.
app.UseSecurityHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    // Not behind a proxy: the proxy owns this header, and two of them is one
    // too many.
    if (ProxySetup.ShouldRedirectToHttps(app.Configuration)) { app.UseHsts(); }
}

if (ProxySetup.ShouldRedirectToHttps(app.Configuration))
{
    app.UseHttpsRedirection();
}
// A URL that matches nothing used to return 404 with an empty body, which is
// a blank white page with no layout and no way back. The status code stays a
// real 404 for anything reading it; only what a person sees changes.
//
// Not for /.well-known, though. Re-executing a 404 runs it back through the
// pipeline as a request for a page, and that page needs authentication, so a
// missing MTA-STS policy answered a sending mail server with 302 to a sign-in
// screen instead of a clean 404. Senders do not follow redirects when fetching
// a policy - RFC 8461 §3.3 - so it was not a security problem, but it is the
// wrong answer to a machine that is not a person and cannot sign in.
app.UseWhen(
    context => !context.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseStatusCodePagesWithReExecute("/not-found"));

app.UseStaticFiles();
app.UseAntiforgery();

app.UseLocalModeGuard();
app.UseAuthentication();
app.UseAuthorization();

app.MapLocalSignIn();
app.MapOrganizationSwitch();
if (AuthSetup.IsEntraConfigured(app.Configuration))
{
    app.MapControllers();   // Microsoft.Identity.Web.UI provides sign-in/out
}

// The other half of MTA-STS.
//
// A TXT record at _mta-sts announces a policy; this is the policy. RFC 8461
// has senders fetch it from mta-sts.<domain>/.well-known/mta-sts.txt over
// HTTPS, so which domain is being asked about comes from the Host header and
// nothing else - one instance serves every client's policy, and each client's
// mta-sts subdomain is a CNAME pointing here.
//
// Anonymous, necessarily: the callers are other people's mail servers. It
// discloses nothing that is not meant to be world-readable - the policy only
// says which servers may receive this domain's mail, which is already public
// in its MX records.
app.MapGet("/.well-known/mta-sts.txt", async (
    HttpContext context, MtaStsStore policies, CancellationToken ct) =>
{
    var host = context.Request.Host.Host;

    // Only ever "mta-sts.<domain>". A request on any other name is not a
    // sender asking about a domain, and answering it would let this instance
    // be used to claim a policy for a name nobody asked about.
    if (!host.StartsWith("mta-sts.", StringComparison.OrdinalIgnoreCase))
    {
        return Results.NotFound();
    }

    var policy = await policies.GetAsync(host["mta-sts.".Length..], ct).ConfigureAwait(false);
    if (policy is null) { return Results.NotFound(); }

    // text/plain is what the RFC requires, and senders check it.
    return Results.Text(policy.ToFile(), "text/plain; charset=utf-8");
}).AllowAnonymous();

// The report as a file, rendered by the same code the CLI uses. A download
// rather than a page: this is a document that gets attached to an email and
// printed, not something to read in the app. The fallback authorization
// policy covers this endpoint like any other.
app.MapGet("/reports/download/{slug}/{month}", async (
    HttpContext context, string slug, string month, ReportUiService reports,
    DmarcMonitor.Core.Tenancy.OrganizationStore organizations, CancellationToken ct) =>
{
    if (!ReportUiService.TryParseMonth(month, out var period))
    {
        return Results.BadRequest("Month must look like 2026-08.");
    }

    // Scoped like every page: a slug guessed for another organization's
    // customer is not found, not served. Resolved from the request's own
    // principal, because there is no component here to hold an
    // authentication state.
    var access = OrgContext.Resolve(
        context.User, await organizations.ListAsync(ct).ConfigureAwait(false), app.Configuration,
        await organizations.ClientGroupsAsync(ct).ConfigureAwait(false));
    if (access.RestrictedClient is { } only && !only.Equals(slug, StringComparison.OrdinalIgnoreCase))
    {
        // A customer's login gets their own report and nobody else's.
        return Results.NotFound($"No client filed as '{slug}'.");
    }

    var report = await reports.BuildAsync(slug, period, access.TenantId, ct).ConfigureAwait(false);
    if (report is null) { return Results.NotFound($"No client filed as '{slug}'."); }

    var html = ClientReportRenderer.ToHtml(report);

    // Inline rather than an attachment: the operator opening this is checking
    // it before sending it, and a download that lands in a folder unread is
    // how an unchecked report reaches a customer.
    return Results.Content(html, "text/html; charset=utf-8");
});

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

// Say plainly at startup which mode this is. An operator who cannot tell
// whether sign-in is on has no way to notice that it is not.
var logger = app.Services.GetRequiredService<ILogger<Program>>();
if (AuthSetup.IsEntraConfigured(app.Configuration))
{
    StartupLog.SignInEntra(logger);
}
else if (AuthSetup.LocalModeAllowedRemotely(app.Configuration))
{
    StartupLog.SignInNoneRemote(logger);
}
else
{
    StartupLog.SignInNoneLocal(logger);
}
StartupLog.Database(logger, dbPath);

await app.RunAsync();

/// <summary>
/// Exists so the test host can start this application in process.
/// </summary>
/// <remarks>
/// Top-level statements generate an internal Program class, which
/// WebApplicationFactory cannot reach. Declaring it partial and public is the
/// documented way to make the app testable without changing how it runs.
/// </remarks>
public partial class Program;
