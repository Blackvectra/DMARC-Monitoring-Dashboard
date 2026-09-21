using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Core.Tests.Tenancy;

/// <summary>
/// Who sees what.
///
/// This is the rule that keeps one company's clients out of another's view,
/// so it is tested as a table rather than by signing in as twelve different
/// people. Every case here is a person, their groups, and what they get.
/// </summary>
public sealed class OrganizationAccessTests
{
    private const string NrgGroup = "11111111-1111-1111-1111-111111111111";
    private const string NlsGroup = "22222222-2222-2222-2222-222222222222";
    private const string MasterGroup = "99999999-9999-9999-9999-999999999999";

    private static readonly Organization Nrg = new("t-nrg", "NRG Tech Services", "nrg-tech-services", NrgGroup, 3, 10);
    private static readonly Organization Nls = new("t-nls", "NextLayerSec", "nextlayersec", NlsGroup, 2, 2);
    private static readonly Organization Ungrouped = new("t-x", "Nobody's", "nobodys", null, 0, 0);

    private static readonly IReadOnlyList<Organization> All = [Nrg, Nls, Ungrouped];

    [Fact]
    public void AnInstallWithNoSignInSeesEverything()
    {
        // The machine is the boundary, as it is for the rest of local mode.
        var access = OrganizationAccess.Resolve(All, [], masterGroupId: null, chosenSlug: null, everyoneIsMaster: true);

        Assert.True(access.IsMaster);
        Assert.Equal(3, access.Visible.Count);
        Assert.Null(access.Current);
        Assert.Null(access.TenantId);
        Assert.True(access.HasAccess);
    }

    [Fact]
    public void TheMasterGroupSeesEveryOrganizationAtOnce()
    {
        var access = OrganizationAccess.Resolve(All, [MasterGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.True(access.IsMaster);
        Assert.Equal(3, access.Visible.Count);
        Assert.Null(access.Current);
        Assert.Null(access.TenantId);
        Assert.True(access.CanSwitch);
    }

    [Fact]
    public void AMasterCanNarrowToOneOrganization()
    {
        var access = OrganizationAccess.Resolve(All, [MasterGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);

        Assert.Same(Nls, access.Current);
        Assert.Equal("t-nls", access.TenantId);
        Assert.Equal(3, access.Visible.Count);
    }

    [Fact]
    public void AnEmployeeOfOneOrganizationSeesOnlyIt()
    {
        var access = OrganizationAccess.Resolve(All, [NrgGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.False(access.IsMaster);
        Assert.Single(access.Visible);
        Assert.Same(Nrg, access.Current);
        Assert.Equal("t-nrg", access.TenantId);
        Assert.False(access.CanSwitch);
    }

    [Fact]
    public void SomebodyInTwoOrganizationsLandsInTheFirstAndMaySwitch()
    {
        var access = OrganizationAccess.Resolve(All, [NlsGroup, NrgGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(2, access.Visible.Count);
        Assert.Same(Nrg, access.Current);   // list order, not group order
        Assert.True(access.CanSwitch);

        var switched = OrganizationAccess.Resolve(All, [NlsGroup, NrgGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);
        Assert.Same(Nls, switched.Current);
    }

    [Fact]
    public void SomebodyInNoGroupHasNoAccessAndScopesToNothing()
    {
        // The important case. Signed in, belongs to nothing: the scope must
        // match no row, so a page that forgot to check renders empty rather
        // than rendering everyone's data.
        var access = OrganizationAccess.Resolve(All, ["33333333-3333-3333-3333-333333333333"], MasterGroup, null, everyoneIsMaster: false);

        Assert.False(access.HasAccess);
        Assert.Empty(access.Visible);
        Assert.Null(access.Current);
        Assert.Equal(OrganizationAccess.NoAccessTenantId, access.TenantId);
        Assert.NotNull(access.TenantId);
    }

    [Fact]
    public void AChoiceOutsideWhatIsVisibleIsIgnored()
    {
        // A stale cookie from before somebody was removed from a group.
        var access = OrganizationAccess.Resolve(All, [NrgGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);

        Assert.Same(Nrg, access.Current);
    }

    [Fact]
    public void AnOrganizationWithNoGroupIsSeenOnlyByTheMaster()
    {
        var employee = OrganizationAccess.Resolve(All, [NrgGroup, NlsGroup], MasterGroup, null, everyoneIsMaster: false);
        Assert.DoesNotContain(Ungrouped, employee.Visible);

        var master = OrganizationAccess.Resolve(All, [MasterGroup], MasterGroup, null, everyoneIsMaster: false);
        Assert.Contains(Ungrouped, master.Visible);
    }

    [Fact]
    public void GroupIdsMatchWhateverTheirCase()
    {
        var access = OrganizationAccess.Resolve(All, [NrgGroup.ToUpperInvariant()], MasterGroup.ToUpperInvariant(), null, everyoneIsMaster: false);

        Assert.Same(Nrg, access.Current);
    }

    [Fact]
    public void NoMasterGroupConfiguredMeansNobodyIsMaster()
    {
        var access = OrganizationAccess.Resolve(All, [MasterGroup], masterGroupId: null, chosenSlug: null, everyoneIsMaster: false);

        Assert.False(access.IsMaster);
        Assert.False(access.HasAccess);
    }

    // ---- roles ---------------------------------------------------------------

    private const string NrgAdmins = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string NrgViewers = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string CustomerGroup = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    private static readonly Organization Roled =
        new("t-nrg", "NRG Tech Services", "nrg-tech-services", NrgGroup, 3, 10, NrgAdmins, NrgViewers);

    private static readonly IReadOnlyList<Organization> Roles = [Roled, Nls];

    [Fact]
    public void AViewerReadsAndDoesNotOperate()
    {
        var access = OrganizationAccess.Resolve(Roles, [NrgViewers], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Viewer, access.CurrentRole);
        Assert.False(access.CanOperate);
        Assert.False(access.CanAdminister);
        Assert.Equal("t-nrg", access.TenantId);
    }

    [Fact]
    public void AnOperatorOperatesButDoesNotAdminister()
    {
        var access = OrganizationAccess.Resolve(Roles, [NrgGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Operator, access.CurrentRole);
        Assert.True(access.CanOperate);
        Assert.False(access.CanAdminister);
    }

    [Fact]
    public void AnAdminDoesBoth()
    {
        var access = OrganizationAccess.Resolve(Roles, [NrgAdmins], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Admin, access.CurrentRole);
        Assert.True(access.CanOperate);
        Assert.True(access.CanAdminister);
    }

    [Fact]
    public void TheStrongestGroupWins()
    {
        // Somebody in all three groups is an admin, not a viewer. Adding
        // somebody to a stronger group must not require removing them from
        // the weaker one first.
        var access = OrganizationAccess.Resolve(Roles, [NrgViewers, NrgGroup, NrgAdmins], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Admin, access.CurrentRole);
    }

    [Fact]
    public void AMasterIsMasterOfEveryOrganization()
    {
        var access = OrganizationAccess.Resolve(Roles, [MasterGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);

        Assert.Equal(OrganizationRole.Master, access.CurrentRole);
        Assert.True(access.CanAdminister);
        Assert.Null(access.RestrictedClient);
    }

    [Fact]
    public void ACustomerSeesOneClientReadOnly()
    {
        // The customer's own login: read only, and confined to their client.
        ClientGroup[] clients = [new("nrg-tech-services", "morton-nd", "Morton, ND", CustomerGroup)];

        var access = OrganizationAccess.Resolve(Roles, [CustomerGroup], MasterGroup, null, everyoneIsMaster: false, clients);

        Assert.Same(Roled, access.Current);
        Assert.Equal(OrganizationRole.Viewer, access.CurrentRole);
        Assert.False(access.CanOperate);
        Assert.Equal("morton-nd", access.RestrictedClient);
        Assert.Single(access.Visible);
    }

    [Fact]
    public void BeingStaffBeatsBeingACustomer()
    {
        // An employee who is also in a customer group must not be locked into
        // that one client.
        ClientGroup[] clients = [new("nrg-tech-services", "morton-nd", "Morton, ND", CustomerGroup)];

        var access = OrganizationAccess.Resolve(Roles, [CustomerGroup, NrgGroup], MasterGroup, null, everyoneIsMaster: false, clients);

        Assert.Equal(OrganizationRole.Operator, access.CurrentRole);
        Assert.Null(access.RestrictedClient);
    }

    [Fact]
    public void ACustomerOfAnotherOrganizationIsNotConfinedHere()
    {
        // The restriction belongs to the organization the client is in. In
        // any other organization it must not leak in as a filter.
        ClientGroup[] clients = [new("nextlayersec", "acme", "Acme", CustomerGroup)];

        var access = OrganizationAccess.Resolve(Roles, [CustomerGroup, NrgGroup], MasterGroup, "nrg-tech-services", everyoneIsMaster: false, clients);

        Assert.Same(Roled, access.Current);
        Assert.Null(access.RestrictedClient);

        var atTheirOwn = access with { Current = Nls };
        Assert.Equal("acme", atTheirOwn.RestrictedClient);
    }
}
