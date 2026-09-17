using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Web;
using DmarcMonitor.Web.Auth;
using DmarcMonitor.Web.Components;
using DmarcMonitor.Web.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.AddAppAuthentication();

// One database path, resolved once to an absolute path, so a misconfiguration
// is a startup problem rather than a page that renders empty and looks like no
// data. Absolute matters for what the pages say too: "no database at dmarc.db"
// sends an operator looking in the wrong directory, because a relative path is
// resolved against wherever the service happened to be started.
var dbPath = Path.GetFullPath(builder.Configuration["Database:Path"] ?? "dmarc.db");
builder.Services.AddSingleton(new DatabaseInfo(dbPath));
builder.Services.AddSingleton<ReportStoreConnection>();
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Rollout.TriageService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Intelligence.CorrelationService(dbPath));
builder.Services.AddScoped(_ => new DmarcMonitor.Core.Domains.DomainDetailService(dbPath));

// The one write path a page has. See OnboardingService for why it is an
// exception to the read-only rule rather than a loosening of it.
builder.Services.AddScoped<OnboardingService>();
builder.Services.AddScoped<ImportUiService>();
builder.Services.AddScoped<ReportUiService>();

// Shared, because it caches: a page opened twice in a minute should not ask
// the resolver twice. Reading DNS is also the only thing here that reaches
// outside the machine, so it is the one service whose slowness can be seen.
builder.Services.AddSingleton(_ => new DmarcMonitor.Core.Dns.DnsLookup());

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.UseLocalModeGuard();
app.UseAuthentication();
app.UseAuthorization();

app.MapLocalSignIn();
if (AuthSetup.IsEntraConfigured(app.Configuration))
{
    app.MapControllers();   // Microsoft.Identity.Web.UI provides sign-in/out
}

// The report as a file, rendered by the same code the CLI uses. A download
// rather than a page: this is a document that gets attached to an email and
// printed, not something to read in the app. The fallback authorization
// policy covers this endpoint like any other.
app.MapGet("/reports/download/{slug}/{month}", async (
    string slug, string month, ReportUiService reports, CancellationToken ct) =>
{
    if (!ReportUiService.TryParseMonth(month, out var period))
    {
        return Results.BadRequest("Month must look like 2026-08.");
    }

    var report = await reports.BuildAsync(slug, period, ct).ConfigureAwait(false);
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
