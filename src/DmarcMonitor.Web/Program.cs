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
builder.Services.AddScoped<TriageService>();
builder.Services.AddScoped<CorrelationService>();
builder.Services.AddScoped<DomainDetailService>();

// The one write path a page has. See OnboardingService for why it is an
// exception to the read-only rule rather than a loosening of it.
builder.Services.AddScoped<OnboardingService>();

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
