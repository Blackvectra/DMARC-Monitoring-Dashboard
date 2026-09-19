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
/// The object id of the Entra security group whose members belong here, or
/// null when nobody but the master group can see it.
/// </param>
public sealed record Organisation(
    string Id,
    string Name,
    string Slug,
    string? EntraGroupId,
    int Clients,
    int Domains);

/// <summary>
/// What one signed-in person may see, worked out from their groups.
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

    /// <summary>False for somebody who signed in and belongs to nothing.</summary>
    public bool HasAccess => IsMaster || Visible.Count > 0;

    /// <summary>Whether a switcher is worth drawing.</summary>
    public bool CanSwitch => IsMaster ? Visible.Count > 0 : Visible.Count > 1;

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
    public static OrganisationAccess Resolve(
        IReadOnlyList<Organisation> all,
        IReadOnlyCollection<string> groupIds,
        string? masterGroupId,
        string? chosenSlug,
        bool everyoneIsMaster)
    {
        ArgumentNullException.ThrowIfNull(all);
        ArgumentNullException.ThrowIfNull(groupIds);

        var groups = new HashSet<string>(groupIds.Where(g => !string.IsNullOrWhiteSpace(g)), StringComparer.OrdinalIgnoreCase);

        var isMaster = everyoneIsMaster
            || (!string.IsNullOrWhiteSpace(masterGroupId) && groups.Contains(masterGroupId.Trim()));

        var visible = isMaster
            ? all
            : [.. all.Where(o => !string.IsNullOrWhiteSpace(o.EntraGroupId) && groups.Contains(o.EntraGroupId.Trim()))];

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

        return new OrganisationAccess { Visible = visible, IsMaster = isMaster, Current = current };
    }
}
