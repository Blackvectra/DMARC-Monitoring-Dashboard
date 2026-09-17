using DmarcMonitor.Web.Auth;
using DmarcMonitor.Web.Components;
using DmarcMonitor.Web.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.AddAppAuthentication();

// One database path, resolved once, so a misconfiguration is a startup
// problem rather than a page that renders empty and looks like no data.
var dbPath = builder.Configuration["Database:Path"] ?? "dmarc.db";
builder.Services.AddSingleton(new DatabaseInfo(dbPath));
builder.Services.AddSingleton<ReportStoreConnection>();
builder.Services.AddScoped<TriageService>();

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
    logger.LogInformation("Sign-in: Microsoft Entra.");
}
else if (AuthSetup.LocalModeAllowedRemotely(app.Configuration))
{
    logger.LogWarning(
        "Sign-in: NONE. Local trial mode is serving every address because Auth:AllowLocalModeRemotely is set. "
        + "Anyone who can reach this port can read every customer's mail data.");
}
else
{
    logger.LogWarning("Sign-in: NONE (local trial mode). Only this machine can reach it.");
}
logger.LogInformation("Database: {Path}", Path.GetFullPath(dbPath));

await app.RunAsync();
