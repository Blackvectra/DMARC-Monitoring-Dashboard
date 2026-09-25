using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Web;
using DmarcMonitor.Web.Auth;
using DmarcMonitor.Web.Components;
using DmarcMonitor.Web.Data;
using Microsoft.AspNetCore.DataProtection;

// Content root beside the executable rather than wherever it happened to be
// started from. That is where wwwroot is, and ASP.NET Core's default - the
// current working directory - is only the same thing by luck.
//
// Both deployments already pin it: the systemd unit sets
// WorkingDirectory=/opt/dmarc/app and bootstrap.ps1 passes --contentRoot, so
// neither changes. What changes is every other way it can be started - a
// shortcut with a different "start in", a terminal in another directory, the
// portable Windows copy launched from anywhere but its own folder - where it
// used to log "The WebRootPath was not found" and serve the whole application
// unstyled. An explicit --contentRoot still wins over this.
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

// On Windows the app runs as a service (deploy/bootstrap.ps1 installs it as
// one). Without this the process never tells the Service Control Manager it
// has started, and the SCM kills it after thirty seconds as "failed to
// respond" - a service that runs perfectly for half a minute and then dies,
// which reads as a crash. On Linux, or when started from a shell anywhere,
// this is a no-op.
builder.Host.UseWindowsService();

// The receive limit is raised from its 32 KB default for one reason: the
// zone-file box on the domain page. A paste arrives as a single hub message,
// and a zone for a domain with a few hundred records is comfortably past the
// default - where what an operator sees is not an error but the page going
// quiet, because the circuit is torn down under them. The cap that says no is
// ZoneAuditUiService.MaxCharacters, which says so in a sentence.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddHubOptions(options => options.MaximumReceiveMessageSize = 512 * 1024);
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

// What each domain publishes, as last read by the scheduled scan. Reads
// storage rather than DNS, because the domains table would otherwise resolve
// every row on every render.
builder.Services.AddScoped<DnsStatusService>();

// The zone-file box on the domain page: the one input an operator can give
// this that it cannot fetch for itself.
builder.Services.AddScoped<ZoneAuditUiService>();

// What is kept and for how long. The app never prunes anything - that is
// dmarc-prune's job, and a web request must not be able to start deleting a
// customer's history - but Settings has to be able to say what the window is
// without an operator reading a unit file.
builder.Services.AddSingleton(new DmarcMonitor.Core.Storage.RetentionPolicy());

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
// The TLS reports that have been arriving with nowhere to be read. Scoped
// like the other read services; it opens its own read-only connection.
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Tls.TlsReportService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Forensic.ForensicReportService(dbPath));
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.MtaStsStore(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Dns.DnsDriftStore(dbPath));
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.MtaStsFetcher());
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Updates.ReleaseChannel());

// Where the app writes down a version it would like installed. It writes a
// version and nothing else; a separate unit with the privileges to do the
// work checks it and acts. See UpdateSpool for why the app is not allowed to
// install anything itself.
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Updates.UpdateSpool(
    Path.Combine(Path.GetDirectoryName(dbPath) ?? ".", "updates")));

// Where a startup failure gets written down. Beside the database, because
// that is the one directory this application is known to be able to write to,
// and because it is the folder somebody will be looking in.
var reportTo = Path.GetDirectoryName(dbPath) ?? AppContext.BaseDirectory;

WebApplication app;
try
{
    app = builder.Build();
}
catch (Exception ex)
{
    // A service resolved wrongly, or a configuration value is not what its
    // type says. On a desktop this used to be a window that closed.
    return StartupFailure.Report(ex, reportTo);
}

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

// Explicit, and it has to be HERE: below the re-execute and above the
// endpoints. Without it the framework inserts routing at the TOP of the
// pipeline, so by the time a 404 comes back up, routing has already happened
// and re-executing only changes the path - nothing routes it again, no
// endpoint matches, and the answer is a 404 with an empty body. Which is
// precisely what the middleware above exists to prevent, and what it was
// quietly doing.
app.UseRouting();

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

// The report as a document, rendered by the same code the CLI uses, so a copy
// opened from the browser is the copy `dmarc report` writes.
//
// PDF, because this is what a client receives. It used to be HTML with a note
// on the page telling the operator to turn the browser's headers and footers
// off before printing - which is a product asking somebody to remember
// something every month, and the month they forget, "localhost:5000" goes out
// across the foot of a document a customer is paying for. ?format=html still
// serves the long on-screen version, which is for reading here, not sending.
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

    // Refused, not merely warned about. The page warned and still offered the
    // link, which is a page telling somebody what to ignore - and a report
    // duly reached a customer signed "prepared by your IT provider",
    // literally. Asked of the finished report rather than of configuration,
    // because an organization with its own name on the Configuration page
    // produces correctly signed reports on an install whose
    // Reporting:ProviderName is blank.
    if (report.ProviderIsUnnamed)
    {
        return Results.Problem(
            $"This report would be signed \"{ClientReport.UnnamedProvider}\", literally. Set "
            + "Reporting:ProviderName in appsettings.json, or give this organization a name on the "
            + "Configuration page, and it can be opened.",
            statusCode: StatusCodes.Status409Conflict);
    }

    if (string.Equals(context.Request.Query["format"], "html", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Content(ClientReportRenderer.ToHtml(report), "text/html; charset=utf-8");
    }

    // Inline rather than an attachment: the operator opening this is checking
    // it before sending it, and a download that lands in a folder unread is
    // how an unchecked report reaches a customer. The filename is what they
    // get if they then save it, and is built from the slug rather than from
    // the client's name, which can contain anything a person typed.
    var stem = new string([.. slug.Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')]);
    if (stem.Length == 0) { stem = "report"; }

    context.Response.Headers.ContentDisposition =
        $"inline; filename=\"{stem}-{report.PeriodFileTag}.pdf\"";

    return Results.File(ClientReportPdf.Render(report), "application/pdf");
});

// Since .NET 9 Blazor stamps its own "frame-ancestors 'self'" policy on
// interactive pages, and SecurityHeaders steps aside for a policy already
// present - so the app's whole policy, frame-ancestors 'none' included, went
// missing. Ours is stricter on framing and covers everything else.
app.MapRazorComponents<App>().AddInteractiveServerRenderMode(o => o.ContentSecurityFrameAncestorsPolicy = null);

// Everything from here can fail in a way somebody on a desktop has to be
// told about: the port is taken, the folder is read-only, the database will
// not open. Under systemd the journal catches all of it; in a window Explorer
// created, nothing does. See StartupFailure.
try
{
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

    // Before the first request, not on the first request. A managed install
    // has already run `dmarc init-db` by this point and this does nothing; a
    // copy somebody downloaded and double-clicked has not, and without this
    // every page reports a table that does not exist.
    //
    // The same is true a second time over on the upgrade. A new release is
    // extracted to a new folder, so somebody carrying their database across
    // brings one built by an older schema - and the only thing that used to
    // bring it up to date was a command named nowhere they would look. In the
    // trial this now happens by itself; on a server it does not, because
    // migrating a production database is a decision an operator makes and
    // deploy/update.sh already makes it out loud.
    await FirstRun
        .EnsureDatabaseAsync(dbPath, logger, mayUpgrade: AuthSetup.IsLocalTrial(app.Configuration))
        .ConfigureAwait(false);

    // Only ever for the Windows trial download - see TrialBrowser for the four
    // cases this is deliberately not. Hooked to ApplicationStarted so the
    // address is the one Kestrel actually bound, and so nothing opens if
    // startup fails.
    if (TrialBrowser.ShouldOpen(app.Configuration))
    {
        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var address = app.Urls.FirstOrDefault() ?? "http://localhost:5000";
            TrialBrowser.Open(address.Replace("0.0.0.0", "localhost", StringComparison.Ordinal), logger);
        });
    }

    await app.RunAsync();
}
catch (Exception ex)
{
    return StartupFailure.Report(ex, reportTo);
}

return 0;

/// <summary>
/// Exists so the test host can start this application in process.
/// </summary>
/// <remarks>
/// Top-level statements generate an internal Program class, which
/// WebApplicationFactory cannot reach. Declaring it partial and public is the
/// documented way to make the app testable without changing how it runs.
/// </remarks>
public partial class Program;
