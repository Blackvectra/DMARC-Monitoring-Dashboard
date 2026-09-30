using System.Security.Claims;
using System.Text.Json;
using DmarcMonitor.Core.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;

namespace DmarcMonitor.Web.Auth;

/// <summary>
/// Which organization the signed-in person is looking at, and which they may.
///
/// Read from the person's claims and nothing else: their Entra groups decide
/// what they may see, and the organization they switched to is carried as a
/// claim of its own, re-signed into the cookie by the switch endpoint. Claims
/// are the one thing that reaches an interactive page reliably - the request
/// that opened the circuit is long gone by the time a page renders, and
/// reading a cookie from inside a circuit is a guess.
/// </summary>
public sealed class OrgContext(
    AuthenticationStateProvider auth,
    OrganizationStore organizations,
    IConfiguration configuration)
{
    /// <summary>The claim carrying the organization a person switched to.</summary>
    public const string ChoiceClaim = "dmarc:org";

    /// <summary>The configuration key naming the group that sees every organization.</summary>
    public const string MasterGroupKey = "Auth:MasterGroupId";

    public async Task<OrganizationAccess> GetAsync(CancellationToken ct = default)
    {
        var state = await auth.GetAuthenticationStateAsync().ConfigureAwait(false);
        var all = await organizations.ListAsync(ct).ConfigureAwait(false);
        var clientGroups = await organizations.ClientGroupsAsync(ct).ConfigureAwait(false);
        return Resolve(state.User, all, configuration, clientGroups);
    }

    /// <summary>
    /// The organization new domains are filed under from a page: the one being
    /// looked at, or the built-in one when a master is looking at everything.
    /// </summary>
    public static string OrganizationFor(OrganizationAccess access) =>
        access.Current?.Slug ?? DmarcMonitor.Core.Storage.ReportStore.DefaultTenantSlug;

    public static OrganizationAccess Resolve(
        ClaimsPrincipal user, IReadOnlyList<Organization> all, IConfiguration configuration,
        IReadOnlyList<ClientGroup>? clientGroups = null) =>
        OrganizationAccess.Resolve(
            all,
            GroupIds(user),
            configuration[MasterGroupKey],
            user.FindFirst(ChoiceClaim)?.Value,
            // No sign-in means the machine is the boundary, and whoever is at
            // it sees everything - the same rule local mode applies to the
            // rest of the data.
            everyoneIsMaster: !AuthSetup.IsEntraConfigured(configuration),
            clientGroups,
            user: user.Identity?.Name ?? Environment.UserName);

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

    /// <summary>
    /// Whether Microsoft left the group list out of this person's token because
    /// they are in too many groups for it to carry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This app signs in with the ID-token flow, and for that flow Entra stops
    /// listing groups above a handful (Microsoft documents five or six). It
    /// does not send a truncated list; it sends none, plus a marker:
    /// <c>hasgroups</c> for the implicit flow, <c>_claim_names</c> naming
    /// <c>groups</c> for the others.
    /// </para>
    /// <para>
    /// The person who set this up is very likely to be in more groups than
    /// that - an engineer at a provider belongs to a group for everything - and
    /// without this check the result is indistinguishable from never having
    /// been added to the master group: the same "No organization" page, after
    /// they have added themselves to it. So the page asks for this first.
    /// </para>
    /// </remarks>
    public static bool GroupsOmitted(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        // Groups present means nothing was left out, whatever else is there.
        if (GroupIds(user).Count > 0) { return false; }

        foreach (var claim in user.Claims)
        {
            if (claim.Type == "hasgroups"
                && bool.TryParse(claim.Value, out var has) && has)
            {
                return true;
            }

            if (claim.Type == "_claim_names" && NamesGroups(claim.Value)) { return true; }
        }

        return false;
    }

    /// <summary>
    /// Whether the value of a <c>_claim_names</c> claim - a JSON object such as
    /// <c>{"groups":"src1"}</c> - has a <c>groups</c> entry.
    /// </summary>
    private static bool NamesGroups(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("groups", out _);
        }
        catch (JsonException)
        {
            // Not the shape Entra sends. Not evidence of anything.
            return false;
        }
    }

    /// <summary>
    /// <see cref="GroupsOmitted"/> for whoever is signed in now.
    /// </summary>
    public async Task<bool> GroupsOmittedAsync()
    {
        var state = await auth.GetAuthenticationStateAsync().ConfigureAwait(false);
        return GroupsOmitted(state.User);
    }
}

/// <summary>The endpoint that records a switch of organization.</summary>
public static class OrganizationSwitch
{
    /// <summary>
    /// Records a switch of organization by re-signing the cookie with the
    /// choice as a claim, then goes back to where the person was.
    /// </summary>
    /// <remarks>
    /// Only a visible organization can be chosen, and only a master can
    /// choose all of them; anything else is refused rather than stored, so a
    /// hand-typed slug cannot become a door.
    /// </remarks>
    public static void MapOrganizationSwitch(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet("/org/switch", async (
            HttpContext context, string? slug, string? returnUrl,
            OrganizationStore organizations, IConfiguration configuration, CancellationToken ct) =>
        {
            // A GET that re-signs the cookie, reachable from any other site:
            // with Entra the cookie is SameSite=Lax, so a link elsewhere could
            // quietly switch a signed-in operator's organization, and the next
            // write on a page they already had open would land in the wrong
            // one. Every browser in use says where a request came from; one
            // from another site is refused. Absent - a script, an old browser
            // - it is allowed, because the risk is a browser following a link.
            if (context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var site)
                && site.ToString().Equals("cross-site", StringComparison.OrdinalIgnoreCase))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var access = OrgContext.Resolve(
                context.User,
                await organizations.ListAsync(ct).ConfigureAwait(false),
                configuration,
                await organizations.ClientGroupsAsync(ct).ConfigureAwait(false));

            var wanted = string.IsNullOrWhiteSpace(slug) ? null : slug.Trim().ToLowerInvariant();
            var chosen = wanted is null
                ? null
                : access.Visible.FirstOrDefault(o => o.Slug.Equals(wanted, StringComparison.OrdinalIgnoreCase));

            if (chosen is null && (wanted is not null || !access.IsMaster))
            {
                return Results.NotFound("That is not an organization you can open.");
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
            return Results.Redirect(LocalUrl.OrRoot(returnUrl));
        });
    }
}
