using System.Security.Claims;
using DmarcMonitor.Core.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;

namespace DmarcMonitor.Web.Auth;

/// <summary>
/// Which organisation the signed-in person is looking at, and which they may.
///
/// Read from the person's claims and nothing else: their Entra groups decide
/// what they may see, and the organisation they switched to is carried as a
/// claim of its own, re-signed into the cookie by the switch endpoint. Claims
/// are the one thing that reaches an interactive page reliably - the request
/// that opened the circuit is long gone by the time a page renders, and
/// reading a cookie from inside a circuit is a guess.
/// </summary>
public sealed class OrgContext(
    AuthenticationStateProvider auth,
    OrganisationStore organisations,
    IConfiguration configuration)
{
    /// <summary>The claim carrying the organisation a person switched to.</summary>
    public const string ChoiceClaim = "dmarc:org";

    /// <summary>The configuration key naming the group that sees every organisation.</summary>
    public const string MasterGroupKey = "Auth:MasterGroupId";

    public async Task<OrganisationAccess> GetAsync(CancellationToken ct = default)
    {
        var state = await auth.GetAuthenticationStateAsync().ConfigureAwait(false);
        var all = await organisations.ListAsync(ct).ConfigureAwait(false);
        return Resolve(state.User, all, configuration);
    }

    /// <summary>
    /// The organisation new domains are filed under from a page: the one being
    /// looked at, or the built-in one when a master is looking at everything.
    /// </summary>
    public static string OrganisationFor(OrganisationAccess access) =>
        access.Current?.Slug ?? DmarcMonitor.Core.Storage.ReportStore.DefaultTenantSlug;

    public static OrganisationAccess Resolve(ClaimsPrincipal user, IReadOnlyList<Organisation> all, IConfiguration configuration) =>
        OrganisationAccess.Resolve(
            all,
            GroupIds(user),
            configuration[MasterGroupKey],
            user.FindFirst(ChoiceClaim)?.Value,
            // No sign-in means the machine is the boundary, and whoever is at
            // it sees everything - the same rule local mode applies to the
            // rest of the data.
            everyoneIsMaster: !AuthSetup.IsEntraConfigured(configuration));

    /// <summary>
    /// The group object ids in the token, under either name Entra uses.
    /// </summary>
    /// <remarks>
    /// The groups claim is only there when the app registration's token
    /// configuration asks for it; without that, everybody belongs to nothing
    /// and the settings page says so.
    /// </remarks>
    public static IReadOnlyCollection<string> GroupIds(ClaimsPrincipal user) =>
        [.. user.Claims
            .Where(c => c.Type is "groups" or "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
            .Select(c => c.Value)];

}

/// <summary>The endpoint that records a switch of organisation.</summary>
public static class OrganisationSwitch
{
    /// <summary>
    /// Records a switch of organisation by re-signing the cookie with the
    /// choice as a claim, then goes back to where the person was.
    /// </summary>
    /// <remarks>
    /// Only a visible organisation can be chosen, and only a master can
    /// choose all of them; anything else is refused rather than stored, so a
    /// hand-typed slug cannot become a door.
    /// </remarks>
    public static void MapOrganisationSwitch(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet("/org/switch", async (
            HttpContext context, string? slug, string? returnUrl,
            OrganisationStore organisations, IConfiguration configuration, CancellationToken ct) =>
        {
            var access = OrgContext.Resolve(context.User, await organisations.ListAsync(ct).ConfigureAwait(false), configuration);

            var wanted = string.IsNullOrWhiteSpace(slug) ? null : slug.Trim().ToLowerInvariant();
            var chosen = wanted is null
                ? null
                : access.Visible.FirstOrDefault(o => o.Slug.Equals(wanted, StringComparison.OrdinalIgnoreCase));

            if (chosen is null && (wanted is not null || !access.IsMaster))
            {
                return Results.NotFound("That is not an organisation you can open.");
            }

            var scheme = AuthSetup.IsEntraConfigured(configuration)
                ? CookieAuthenticationDefaults.AuthenticationScheme
                : AuthSetup.LocalScheme;

            var current = await context.AuthenticateAsync(scheme).ConfigureAwait(false);
            if (current.Principal?.Identity is not ClaimsIdentity identity)
            {
                return Results.Unauthorized();
            }

            var replaced = new ClaimsIdentity(
                identity.Claims.Where(c => c.Type != OrgContext.ChoiceClaim),
                identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
            if (chosen is not null)
            {
                replaced.AddClaim(new Claim(OrgContext.ChoiceClaim, chosen.Slug));
            }

            await context.SignInAsync(scheme, new ClaimsPrincipal(replaced), current.Properties).ConfigureAwait(false);

            // Only ever within this site: an open redirect on an internal tool
            // is a phishing primitive.
            var back = returnUrl ?? "/";
            return Results.Redirect(back.StartsWith('/') && !back.StartsWith("//", StringComparison.Ordinal) ? back : "/");
        });
    }
}
