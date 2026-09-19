using System.Text.RegularExpressions;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// An organisation: the layer above clients.
///
/// NRG Tech Services and NextLayerSec each have their own clients and their
/// own domains, and a person from one must never see the other's. This is the
/// tenants table, which every scoped table has carried an id for from the
/// start; what changed is that it is now filtered on.
/// </summary>
/// <param name="EntraGroupId">
/// The object id of the Entra security group whose members operate here:
/// assign domains, apply fixes, import. Null when nobody but the master
/// group, or an admin or viewer group, can see it.
/// </param>
/// <param name="AdminGroupId">The group whose members also run the organisation's settings.</param>
/// <param name="ViewerGroupId">The group whose members read and change nothing.</param>
public sealed record Organisation(
    string Id,
    string Name,
    string Slug,
    string? EntraGroupId,
    int Clients,
    int Domains,
    string? AdminGroupId = null,
    string? ViewerGroupId = null,
    OrganisationBrand? Brand = null)
{
    /// <summary>How the organisation looks, never null.</summary>
    public OrganisationBrand Brand { get; init; } = Brand ?? OrganisationBrand.None;
}

/// <summary>
/// White-label: what the sidebar and the reports carry for one organisation.
/// </summary>
/// <param name="PrimaryColor">A hex colour, #rrggbb, for the accent. Null keeps the default.</param>
/// <param name="Logo">A small image as a data: URL, or null for the default mark.</param>
/// <param name="ProviderName">How the organisation names itself on reports. Null falls back to configuration.</param>
/// <param name="ContactBlock">Text for the report footer: who to call.</param>
public sealed record OrganisationBrand(string? PrimaryColor, string? Logo, string? ProviderName, string? ContactBlock)
{
    public static readonly OrganisationBrand None = new(null, null, null, null);

    /// <summary>Largest logo accepted, as the data: URL's length. Enough for a crisp PNG, not for a photograph.</summary>
    public const int MaxLogoLength = 200_000;

    public bool IsEmpty => PrimaryColor is null && Logo is null && ProviderName is null && ContactBlock is null;

    /// <summary>
    /// Whether the colour is a plain six-digit hex. Anything else is refused,
    /// because it is interpolated into a stylesheet and an inline style.
    /// </summary>
    public static bool IsValidColor(string? value) =>
        value is null || Regex.IsMatch(value, "^#[0-9a-fA-F]{6}$");

    /// <summary>
    /// Whether the logo is an image data: URL of a type a browser draws and
    /// a size a sidebar can hold. Refused otherwise: it lands in an img src.
    /// </summary>
    public static bool IsValidLogo(string? value) =>
        value is null
        || (value.Length <= MaxLogoLength
            && Regex.IsMatch(value, "^data:image/(png|jpeg|gif|webp|svg\\+xml);base64,[A-Za-z0-9+/=]+$"));
}

/// <summary>A client's own login group, for resolving customer access.</summary>
public sealed record ClientGroup(string OrganisationSlug, string ClientSlug, string ClientName, string EntraGroupId);

/// <summary>
/// What a person may do within an organisation, lowest first.
/// </summary>
public enum OrganisationRole
{
    /// <summary>Not a member.</summary>
    None,

    /// <summary>Reads everything in scope, changes nothing.</summary>
    Viewer,

    /// <summary>Assigns domains, applies fixes, imports.</summary>
    Operator,

    /// <summary>Also runs the organisation's settings: groups, branding, providers.</summary>
    Admin,

    /// <summary>The master group: every organisation, and creating new ones.</summary>
    Master,
}

/// <summary>
/// What one signed-in person may see and do, worked out from their groups.
/// </summary>
/// <remarks>
/// A pure function of its inputs, so the rule that separates one customer's
/// data from another's is tested on a table rather than by signing in as
/// twelve different people.
/// </remarks>
public sealed record OrganisationAccess
{
    /// <summary>The organisations this person may open.</summary>
    public required IReadOnlyList<Organisation> Visible { get; init; }

    /// <summary>In the master group, or on an install with no sign-in: sees every organisation.</summary>
    public required bool IsMaster { get; init; }

    /// <summary>
    /// The organisation being looked at, or null for all of them at once,
    /// which only a master can do.
    /// </summary>
    public Organisation? Current { get; init; }

    /// <summary>The role in each visible organisation, by slug.</summary>
    public IReadOnlyDictionary<string, OrganisationRole> Roles { get; init; } =
        new Dictionary<string, OrganisationRole>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The one client a person is confined to in each organisation, by slug,
    /// for people who came in through a client's own group. Absent for
    /// everybody else.
    /// </summary>
    public IReadOnlyDictionary<string, string> ClientRestrictions { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Who this is, for the audit log. Empty when unknown.</summary>
    public string User { get; init; } = "";

    /// <summary>False for somebody who signed in and belongs to nothing.</summary>
    public bool HasAccess => IsMaster || Visible.Count > 0;

    /// <summary>Whether a switcher is worth drawing.</summary>
    public bool CanSwitch => IsMaster ? Visible.Count > 0 : Visible.Count > 1;

    /// <summary>The role in the organisation being looked at. Master everywhere for a master.</summary>
    public OrganisationRole CurrentRole =>
        IsMaster ? OrganisationRole.Master
        : Current is null ? OrganisationRole.None
        : Roles.GetValueOrDefault(Current.Slug, OrganisationRole.None);

    /// <summary>May assign domains, apply fixes and import here.</summary>
    public bool CanOperate => CurrentRole >= OrganisationRole.Operator;

    /// <summary>May change this organisation's groups, branding and providers.</summary>
    public bool CanAdminister => CurrentRole >= OrganisationRole.Admin;

    /// <summary>The one client this person is confined to here, or null for all of them.</summary>
    public string? RestrictedClient =>
        Current is null ? null : ClientRestrictions.GetValueOrDefault(Current.Slug);

    /// <summary>
    /// What every query is scoped by.
    /// </summary>
    /// <remarks>
    /// Null means unscoped, and only a master looking at everything gets
    /// that. Somebody with no access gets an id that matches no row, so a page
    /// that forgets to check <see cref="HasAccess"/> renders empty rather than
    /// rendering everyone's data. The failure this guards against is the one
    /// that matters most in a product whose whole point is separation.
    /// </remarks>
    public string? TenantId => !HasAccess ? NoAccessTenantId : Current?.Id;

    /// <summary>An id no tenant has. Scoping a query by it returns nothing.</summary>
    public const string NoAccessTenantId = "";

    /// <summary>
    /// Works out access from the groups a person carries.
    /// </summary>
    /// <param name="all">Every organisation.</param>
    /// <param name="groupIds">The group object ids in the person's token.</param>
    /// <param name="masterGroupId">The group that sees everything, or null when there is none.</param>
    /// <param name="chosenSlug">The organisation the person switched to, if any.</param>
    /// <param name="everyoneIsMaster">True on an install with no sign-in, where the machine is the boundary.</param>
    /// <param name="clientGroups">Clients with a login group of their own.</param>
    /// <param name="user">Who this is, for the audit log.</param>
    public static OrganisationAccess Resolve(
        IReadOnlyList<Organisation> all,
        IReadOnlyCollection<string> groupIds,
        string? masterGroupId,
        string? chosenSlug,
        bool everyoneIsMaster,
        IReadOnlyList<ClientGroup>? clientGroups = null,
        string user = "")
    {
        ArgumentNullException.ThrowIfNull(all);
        ArgumentNullException.ThrowIfNull(groupIds);

        var groups = new HashSet<string>(groupIds.Where(g => !string.IsNullOrWhiteSpace(g)).Select(g => g.Trim()), StringComparer.OrdinalIgnoreCase);
        bool In(string? id) => !string.IsNullOrWhiteSpace(id) && groups.Contains(id.Trim());

        var isMaster = everyoneIsMaster || In(masterGroupId);

        var roles = new Dictionary<string, OrganisationRole>(StringComparer.OrdinalIgnoreCase);
        var restrictions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var o in all)
        {
            // The strongest group wins, so somebody in both the viewer and the
            // admin group is an admin; being added to a group never takes
            // anything away.
            var role =
                isMaster ? OrganisationRole.Master
                : In(o.AdminGroupId) ? OrganisationRole.Admin
                : In(o.EntraGroupId) ? OrganisationRole.Operator
                : In(o.ViewerGroupId) ? OrganisationRole.Viewer
                : OrganisationRole.None;

            if (role == OrganisationRole.None && clientGroups is not null)
            {
                // A customer's own group: read only, one client, nothing else
                // of the organisation. The first matching client wins if a
                // person somehow belongs to several; one client per customer
                // is the shape this is for.
                var mine = clientGroups.FirstOrDefault(c =>
                    c.OrganisationSlug.Equals(o.Slug, StringComparison.OrdinalIgnoreCase) && In(c.EntraGroupId));
                if (mine is not null)
                {
                    role = OrganisationRole.Viewer;
                    restrictions[o.Slug] = mine.ClientSlug;
                }
            }

            if (role != OrganisationRole.None) { roles[o.Slug] = role; }
        }

        var visible = isMaster ? all : [.. all.Where(o => roles.ContainsKey(o.Slug))];

        // A choice only counts when it names something this person may see:
        // a stale cookie from before somebody was removed from a group must
        // not keep the door open.
        var chosen = string.IsNullOrWhiteSpace(chosenSlug)
            ? null
            : visible.FirstOrDefault(o => o.Slug.Equals(chosenSlug.Trim(), StringComparison.OrdinalIgnoreCase));

        // A master with no choice sees everything. Anybody else lands in the
        // first organisation they belong to, because "all" is not a view they
        // have.
        var current = chosen ?? (isMaster || visible.Count == 0 ? null : visible[0]);

        return new OrganisationAccess
        {
            Visible = visible,
            IsMaster = isMaster,
            Current = current,
            Roles = roles,
            ClientRestrictions = restrictions,
            User = user,
        };
    }
}
