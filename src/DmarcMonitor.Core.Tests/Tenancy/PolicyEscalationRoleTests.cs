using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Core.Tests.Tenancy;

/// <summary>
/// The one capability that separates a Tech from an Engineer.
///
/// Every other change this product makes exists to get legitimate mail
/// authenticating: an SPF include, a DKIM selector, a flattened record. They
/// get safer as they land, and a Tech does all of them. Raising the DMARC
/// policy is the change that acts on the mail which still does not
/// authenticate - and on any real estate a share of that is a stream nobody
/// remembered to mention: a payroll run, a booking confirmation, a scanner in
/// a warehouse. Getting it wrong does not degrade a report, it bounces
/// somebody's invoice.
///
/// So the seam is "can this bounce real mail?", and these are the cases that
/// hold it in place.
/// </summary>
public sealed class PolicyEscalationRoleTests
{
    private const string TechGroup = "11111111-1111-1111-1111-111111111111";
    private const string EngineerGroup = "44444444-4444-4444-4444-444444444444";
    private const string AdminGroup = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string ViewerGroup = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string MasterGroup = "99999999-9999-9999-9999-999999999999";

    private static readonly Organization Nrg = new(
        "t-nrg", "NRG Tech Services", "nrg", TechGroup, 3, 10,
        AdminGroupId: AdminGroup, ViewerGroupId: ViewerGroup, EngineerGroupId: EngineerGroup);

    private static readonly IReadOnlyList<Organization> All = [Nrg];

    private static OrganizationAccess For(params string[] groups) =>
        OrganizationAccess.Resolve(All, groups, MasterGroup, "nrg", everyoneIsMaster: false);

    [Fact]
    public void AViewerCanNeitherOperateNorEscalate()
    {
        var access = For(ViewerGroup);

        Assert.Equal(OrganizationRole.Viewer, access.CurrentRole);
        Assert.False(access.CanOperate);
        Assert.False(access.CanEscalatePolicy);
    }

    /// <summary>
    /// The case this whole change exists for.
    /// </summary>
    [Fact]
    public void ATechRepairsRecordsButMayNotRaiseAPolicy()
    {
        var access = For(TechGroup);

        Assert.Equal(OrganizationRole.Tech, access.CurrentRole);
        Assert.True(access.CanOperate);
        Assert.False(access.CanEscalatePolicy);
    }

    [Fact]
    public void AnEngineerMayDoBoth()
    {
        var access = For(EngineerGroup);

        Assert.Equal(OrganizationRole.Engineer, access.CurrentRole);
        Assert.True(access.CanOperate);
        Assert.True(access.CanEscalatePolicy);
        Assert.False(access.CanAdminister);
    }

    [Fact]
    public void AnAdminMayEscalateToo()
    {
        // The roles are a ladder, not a set of boxes: everything below an
        // admin is also an admin's. An admin who could configure the engineer
        // group but not use the button it grants would be an odd hole.
        var access = For(AdminGroup);

        Assert.Equal(OrganizationRole.Admin, access.CurrentRole);
        Assert.True(access.CanEscalatePolicy);
        Assert.True(access.CanAdminister);
    }

    [Fact]
    public void AMasterMayEscalateEverywhere()
    {
        var access = OrganizationAccess.Resolve(All, [MasterGroup], MasterGroup, "nrg", everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Master, access.CurrentRole);
        Assert.True(access.CanEscalatePolicy);
    }

    [Fact]
    public void AnInstallWithNoSignInMayEscalate()
    {
        // Local mode: the machine is the boundary, and everybody on it is a
        // master. A trial copy that could not demonstrate the one control the
        // product is bought for would be a poor demonstration.
        var access = OrganizationAccess.Resolve(All, [], masterGroupId: null, "nrg", everyoneIsMaster: true);

        Assert.True(access.CanEscalatePolicy);
    }

    /// <summary>
    /// The upgrade path. Every install that exists today has no engineer
    /// group, and the column is added empty - so this is what those installs
    /// become on the morning after the update, and it must not be a surprise.
    /// </summary>
    [Fact]
    public void WithNoEngineerGroupSetATechStillCannotEscalate()
    {
        var withoutEngineers = new[] { Nrg with { EngineerGroupId = null } };

        var access = OrganizationAccess.Resolve(
            withoutEngineers, [TechGroup], MasterGroup, "nrg", everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Tech, access.CurrentRole);
        Assert.True(access.CanOperate);

        // Deliberate, and the documented consequence: leaving the group unset
        // does not quietly hand the capability back to everybody who had it
        // before. Admins keep it, so nobody is locked out of their own
        // estate, and an organization that wants the ladder used names a
        // group. The alternative - defaulting to "everybody may" - would mean
        // the gate did nothing until somebody noticed it existed.
        Assert.False(access.CanEscalatePolicy);
    }

    [Fact]
    public void TheStrongestGroupStillWins()
    {
        // Somebody in both keeps the higher of the two. Being added to a
        // group has never taken anything away here and must not start.
        Assert.Equal(OrganizationRole.Engineer, For(TechGroup, EngineerGroup).CurrentRole);
        Assert.Equal(OrganizationRole.Admin, For(TechGroup, EngineerGroup, AdminGroup).CurrentRole);
    }

    /// <summary>
    /// The ordering itself, asserted directly. Every gate in the application
    /// is a >= comparison against this enum, so a member inserted in the
    /// wrong place would silently grant or withhold across the whole product
    /// rather than failing anywhere in particular.
    /// </summary>
    [Fact]
    public void TheLadderIsInOrder()
    {
        Assert.True(OrganizationRole.None < OrganizationRole.Viewer);
        Assert.True(OrganizationRole.Viewer < OrganizationRole.Tech);
        Assert.True(OrganizationRole.Tech < OrganizationRole.Engineer);
        Assert.True(OrganizationRole.Engineer < OrganizationRole.Admin);
        Assert.True(OrganizationRole.Admin < OrganizationRole.Master);
    }
}
