using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

namespace DmarcMonitor.Web.Auth;

/// <summary>
/// How somebody signs in.
///
/// Entra single sign-on when it is configured, which is the intended shape:
/// the people using this already have accounts, so MFA, conditional access
/// and — most importantly — offboarding all come for free. Somebody leaves
/// and their access dies with their account, with nothing to remember to do.
///
/// When it is NOT configured, the app runs in local mode rather than refusing
/// to start. An internal trial has to be runnable before anybody has created
/// an app registration, and a product that cannot be started until a tenant
/// admin has done paperwork does not get trialled.
///
/// Local mode is deliberately awkward to deploy by accident: it refuses to
/// serve anything but loopback unless it is explicitly overridden, and says
/// so on every page.
/// </summary>
public static class AuthSetup
{
    public const string LocalScheme = "LocalTrial";

    /// <summary>Whether Entra is configured well enough to use.</summary>
    public static bool IsEntraConfigured(IConfiguration configuration)
    {
        var section = configuration.GetSection("AzureAd");
        return !string.IsNullOrWhiteSpace(section["TenantId"])
            && !string.IsNullOrWhiteSpace(section["ClientId"]);
    }

    /// <summary>True when local mode has been allowed to listen beyond loopback.</summary>
    public static bool LocalModeAllowedRemotely(IConfiguration configuration) =>
        configuration.GetValue("Auth:AllowLocalModeRemotely", false);

    public static void AddAppAuthentication(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (IsEntraConfigured(builder.Configuration))
        {
            builder.Services
                .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

            builder.Services.AddControllersWithViews().AddMicrosoftIdentityUI();
        }
        else
        {
            // A cookie scheme with a single signed-in identity. No password,
            // because there is nothing to protect that is not already
            // protected by the machine: local mode only serves loopback.
            builder.Services
                .AddAuthentication(LocalScheme)
                .AddCookie(LocalScheme, options =>
                {
                    options.Cookie.Name = "dmarc-local";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.LoginPath = "/local-signin";
                    options.ExpireTimeSpan = TimeSpan.FromHours(12);
                });
        }

        builder.Services.AddAuthorization(options =>
        {
            // Everything requires a signed-in user unless a page opts out.
            // Defaulting the other way means one forgotten attribute exposes
            // a customer's mail data.
            options.FallbackPolicy = options.DefaultPolicy;
        });

        builder.Services.AddCascadingAuthenticationState();
    }

    /// <summary>
    /// Refuses to serve local mode to anything but loopback.
    /// </summary>
    /// <remarks>
    /// The failure this prevents is a trial instance left running on a VM with
    /// a public address and no login at all. Blocking it here means that
    /// mistake produces an obvious refusal rather than an open door.
    ///
    /// A reverse proxy defeats the obvious version of this check, because
    /// every request it forwards arrives from the proxy - usually 127.0.0.1.
    /// So a forwarded request is refused on sight, whether or not the
    /// forwarded headers were configured to be trusted. Being proxied is
    /// itself the evidence: somebody has deliberately put this where other
    /// machines can reach it, which is the exact situation local mode must
    /// not be in.
    /// </remarks>
    public static void UseLocalModeGuard(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        if (IsEntraConfigured(app.Configuration)) { return; }
        if (LocalModeAllowedRemotely(app.Configuration)) { return; }

        app.Use(async (context, next) =>
        {
            var remote = context.Connection.RemoteIpAddress;
            var isLoopback = remote is null || System.Net.IPAddress.IsLoopback(remote);
            var wasForwarded = WasForwarded(context.Request);

            if (!isLoopback || wasForwarded)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync(
                    "This instance is running in local trial mode, which has no sign-in, so it only "
                  + "serves the machine it runs on.\n\n"
                  + (wasForwarded
                        ? "This request came through a reverse proxy, which means it was not made from this "
                        + "machine. Local mode refuses those however they are addressed.\n\n"
                        : "")
                  + "To use it from elsewhere, configure Entra sign-in under AzureAd in appsettings.json.\n"
                  + "To deliberately run without sign-in anyway, set Auth:AllowLocalModeRemotely to true.")
                    .ConfigureAwait(false);
                return;
            }

            await next(context).ConfigureAwait(false);
        });
    }

    /// <summary>
    /// Whether a request bears the marks of having passed through a proxy.
    /// </summary>
    /// <remarks>
    /// Read straight off the headers rather than from the forwarded-headers
    /// middleware, on purpose. That middleware only rewrites what it has been
    /// configured to trust, and a deployment that put a proxy in front without
    /// configuring any of it is precisely the one this has to catch. A caller
    /// on this machine forging the header only locks itself out.
    /// </remarks>
    private static bool WasForwarded(HttpRequest request) =>
        request.Headers.ContainsKey("X-Forwarded-For")
        || request.Headers.ContainsKey("X-Forwarded-Proto")
        || request.Headers.ContainsKey("X-Forwarded-Host")
        || request.Headers.ContainsKey("Forwarded");

    /// <summary>Signs the local-mode user in. Only reachable when Entra is not configured.</summary>
    public static void MapLocalSignIn(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (IsEntraConfigured(app.Configuration)) { return; }

        app.MapGet("/local-signin", async (HttpContext context) =>
        {
            var identity = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, Environment.UserName),
                    new Claim(ClaimTypes.NameIdentifier, "local"),
                ],
                LocalScheme);

            await context.SignInAsync(LocalScheme, new ClaimsPrincipal(identity)).ConfigureAwait(false);

            var returnUrl = context.Request.Query["returnUrl"].ToString();
            // Only ever redirect within this site: an open redirect here would
            // be a phishing primitive on an otherwise internal tool.
            context.Response.Redirect(
                returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) ? returnUrl : "/");
        }).AllowAnonymous();
    }
}
