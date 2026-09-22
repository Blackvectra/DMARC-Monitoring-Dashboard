using System.Text.RegularExpressions;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// An organization: the layer above clients.
///
/// NRG Tech Services and NextLayerSec each have their own clients and their
/// own domains, and a person from one must never see the other's. This is the
/// tenants table, which every scoped table has carried an id for from the
/// start; what changed is that it is now filtered on.
/// </summary>
/// <param name="EntraGroupId">
/// The object id of the Entra security group whose members do the day-to-day
/// work here: assign domains, import, run reports and checks, repair SPF and
/// DKIM. The Tech role. Still called entra_group_id in the database, because
/// it is the column that has always held this and renaming it would rewrite
/// every existing install's configuration to say the same thing.
/// </param>
/// <param name="AdminGroupId">The group whose members also run the organization's settings.</param>
/// <param name="ViewerGroupId">The group whose members read and change nothing.</param>
/// <param name="EngineerGroupId">
/// The group whose members may also tighten a DMARC policy. Separated from
/// the Tech group because every other change repairs delivery and this one
/// starts refusing it.
/// </param>
public sealed record Organization(
    string Id,
    string Name,
    string Slug,
    string? EntraGroupId,
    int Clients,
    int Domains,
    string? AdminGroupId = null,
    string? ViewerGroupId = null,
    string? EngineerGroupId = null,
    OrganizationBrand? Brand = null)
{
    /// <summary>How the organization looks, never null.</summary>
    public OrganizationBrand Brand { get; init; } = Brand ?? OrganizationBrand.None;
}

/// <summary>
/// White-label: what the sidebar and the reports carry for one organization.
/// </summary>
/// <param name="PrimaryColor">A hex color, #rrggbb, for the accent. Null keeps the default.</param>
/// <param name="Logo">A small image as a data: URL, or null for the default mark.</param>
/// <param name="ProviderName">How the organization names itself on reports. Null falls back to configuration.</param>
/// <param name="ContactBlock">Text for the report footer: who to call.</param>
public sealed record OrganizationBrand(string? PrimaryColor, string? Logo, string? ProviderName, string? ContactBlock)
{
    public static readonly OrganizationBrand None = new(null, null, null, null);

    /// <summary>Largest logo accepted, as the data: URL's length. Enough for a crisp PNG, not for a photograph.</summary>
    public const int MaxLogoLength = 200_000;

    public bool IsEmpty => PrimaryColor is null && Logo is null && ProviderName is null && ContactBlock is null;

    /// <summary>
    /// Whether the color is a plain six-digit hex. Anything else is refused,
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
public sealed record ClientGroup(string OrganizationSlug, string ClientSlug, string ClientName, string EntraGroupId);

/// <summary>
/// What a person may do within an organization, lowest first.
/// </summary>
public enum OrganizationRole
{
    /// <summary>Not a member.</summary>
    None,

    /// <summary>Reads everything in scope, changes nothing.</summary>
    Viewer,

    /// <summary>
    /// The daily work: assigns domains, imports, runs reports and checks, and
    /// repairs SPF and DKIM.
    /// </summary>
    /// <remarks>
    /// Called Operator until the role was split. The CLI still accepts
    /// "operator" so that written-down commands and runbooks keep working.
    /// </remarks>
    Tech,

    /// <summary>
    /// Also moves a domain up the DMARC ladder: none to quarantine to reject.
    /// </summary>
    /// <remarks>
    /// The one change in this product that can stop a customer's real mail
    /// being delivered. Every other repair - an SPF include, a DKIM selector,
    /// a flattened record - exists to make legitimate mail authenticate;
    /// raising the policy is the step that acts on the ones that still do
    /// not, and the ones that still do not are sometimes a mail stream
    /// nobody remembered to tell you about.
    ///
    /// So it is separated from Tech by the question "can this bounce real
    /// mail?" rather than by seniority, and it is the only capability gate
    /// between them.
    /// </remarks>
    Engineer,

    /// <summary>Also runs the organization's settings: groups, branding, providers.</summary>
    Admin,

    /// <summary>The master group: every organization, and creating new ones.</summary>
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
public sealed record OrganizationAccess
{
    /// <summary>The organizations this person may open.</summary>
    public required IReadOnlyList<Organization> Visible { get; init; }

    /// <summary>In the master group, or on an install with no sign-in: sees every organization.</summary>
    public required bool IsMaster { get; init; }

    /// <summary>
    /// The organization being looked at, or null for all of them at once,
    /// which only a master can do.
    /// </summary>
    public Organization? Current { get; init; }

    /// <summary>The role in each visible organization, by slug.</summary>
    public IReadOnlyDictionary<string, OrganizationRole> Roles { get; init; } =
        new Dictionary<string, OrganizationRole>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The one client a person is confined to in each organization, by slug,
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

    /// <summary>The role in the organization being looked at. Master everywhere for a master.</summary>
    public OrganizationRole CurrentRole =>
        IsMaster ? OrganizationRole.Master
        : Current is null ? OrganizationRole.None
        : Roles.GetValueOrDefault(Current.Slug, OrganizationRole.None);

    /// <summary>May assign domains, import, and repair SPF and DKIM here.</summary>
    public bool CanOperate => CurrentRole >= OrganizationRole.Tech;

    /// <summary>
    /// May move a domain from p=none to quarantine to reject here.
    /// </summary>
    /// <remarks>
    /// Checked in addition to <see cref="CanOperate"/>, never instead of it:
    /// planning a policy change is still an operation, so a Viewer is stopped
    /// by the first gate and a Tech by this one.
    /// </remarks>
    public bool CanEscalatePolicy => CurrentRole >= OrganizationRole.Engineer;

    /// <summary>May change this organization's groups, branding and providers.</summary>
    public bool CanAdminister => CurrentRole >= OrganizationRole.Admin;

    /// <summary>
    /// May read the subject and headers of a message a failure report is
    /// about.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The only gate in this product that is about content rather than about
    /// capability, because failure reports are the only thing here that is
    /// correspondence. Every other page holds counts: how many messages, from
    /// which address, passing or failing. A failure report holds one real
    /// message - who sent it, who it was going to, and what it was about.
    /// </para>
    /// <para>
    /// Set at Tech rather than at Viewer for that reason. Somebody given a
    /// login to watch their domains' compliance has not thereby been given a
    /// window into individual mail, and the commonest Viewer here is a
    /// customer's own account. Whoever is investigating a forgery is an
    /// operator, and that is the role this follows.
    /// </para>
    /// </remarks>
    public bool CanReadMessageContent => CurrentRole >= OrganizationRole.Tech;

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
    /// <param name="all">Every organization.</param>
    /// <param name="groupIds">The group object ids in the person's token.</param>
    /// <param name="masterGroupId">The group that sees everything, or null when there is none.</param>
    /// <param name="chosenSlug">The organization the person switched to, if any.</param>
    /// <param name="everyoneIsMaster">True on an install with no sign-in, where the machine is the boundary.</param>
    /// <param name="clientGroups">Clients with a login group of their own.</param>
    /// <param name="user">Who this is, for the audit log.</param>
    public static OrganizationAccess Resolve(
        IReadOnlyList<Organization> all,
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

        var roles = new Dictionary<string, OrganizationRole>(StringComparer.OrdinalIgnoreCase);
        var restrictions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var o in all)
        {
            // The strongest group wins, so somebody in both the viewer and the
            // admin group is an admin; being added to a group never takes
            // anything away.
            var role =
                isMaster ? OrganizationRole.Master
                : In(o.AdminGroupId) ? OrganizationRole.Admin
                : In(o.EngineerGroupId) ? OrganizationRole.Engineer
                : In(o.EntraGroupId) ? OrganizationRole.Tech
                : In(o.ViewerGroupId) ? OrganizationRole.Viewer
                : OrganizationRole.None;

            if (role == OrganizationRole.None && clientGroups is not null)
            {
                // A customer's own group: read only, one client, nothing else
                // of the organization. The first matching client wins if a
                // person somehow belongs to several; one client per customer
                // is the shape this is for.
                var mine = clientGroups.FirstOrDefault(c =>
                    c.OrganizationSlug.Equals(o.Slug, StringComparison.OrdinalIgnoreCase) && In(c.EntraGroupId));
                if (mine is not null)
                {
                    role = OrganizationRole.Viewer;
                    restrictions[o.Slug] = mine.ClientSlug;
                }
            }

            if (role != OrganizationRole.None) { roles[o.Slug] = role; }
        }

        var visible = isMaster ? all : [.. all.Where(o => roles.ContainsKey(o.Slug))];

        // A choice only counts when it names something this person may see:
        // a stale cookie from before somebody was removed from a group must
        // not keep the door open.
        var chosen = string.IsNullOrWhiteSpace(chosenSlug)
            ? null
            : visible.FirstOrDefault(o => o.Slug.Equals(chosenSlug.Trim(), StringComparison.OrdinalIgnoreCase));

        // A master with no choice sees everything. Anybody else lands in the
        // first organization they belong to, because "all" is not a view they
        // have.
        var current = chosen ?? (isMaster || visible.Count == 0 ? null : visible[0]);

        return new OrganizationAccess
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
