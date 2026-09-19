using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Core.Tests.Tenancy;

/// <summary>
/// Who sees what.
///
/// This is the rule that keeps one company's clients out of another's view,
/// so it is tested as a table rather than by signing in as twelve different
/// people. Every case here is a person, their groups, and what they get.
/// </summary>
public sealed class OrganisationAccessTests
{
    private const string NrgGroup = "11111111-1111-1111-1111-111111111111";
    private const string NlsGroup = "22222222-2222-2222-2222-222222222222";
    private const string MasterGroup = "99999999-9999-9999-9999-999999999999";

    private static readonly Organisation Nrg = new("t-nrg", "NRG Tech Services", "nrg-tech-services", NrgGroup, 3, 10);
    private static readonly Organisation Nls = new("t-nls", "NextLayerSec", "nextlayersec", NlsGroup, 2, 2);
    private static readonly Organisation Ungrouped = new("t-x", "Nobody's", "nobodys", null, 0, 0);

    private static readonly IReadOnlyList<Organisation> All = [Nrg, Nls, Ungrouped];

    [Fact]
    public void AnInstallWithNoSignInSeesEverything()
    {
        // The machine is the boundary, as it is for the rest of local mode.
        var access = OrganisationAccess.Resolve(All, [], masterGroupId: null, chosenSlug: null, everyoneIsMaster: true);

        Assert.True(access.IsMaster);
        Assert.Equal(3, access.Visible.Count);
        Assert.Null(access.Current);
        Assert.Null(access.TenantId);
        Assert.True(access.HasAccess);
    }

    [Fact]
    public void TheMasterGroupSeesEveryOrganisationAtOnce()
    {
        var access = OrganisationAccess.Resolve(All, [MasterGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.True(access.IsMaster);
        Assert.Equal(3, access.Visible.Count);
        Assert.Null(access.Current);
        Assert.Null(access.TenantId);
        Assert.True(access.CanSwitch);
    }

    [Fact]
    public void AMasterCanNarrowToOneOrganisation()
    {
        var access = OrganisationAccess.Resolve(All, [MasterGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);

        Assert.Same(Nls, access.Current);
        Assert.Equal("t-nls", access.TenantId);
        Assert.Equal(3, access.Visible.Count);
    }

    [Fact]
    public void AnEmployeeOfOneOrganisationSeesOnlyIt()
    {
        var access = OrganisationAccess.Resolve(All, [NrgGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.False(access.IsMaster);
        Assert.Single(access.Visible);
        Assert.Same(Nrg, access.Current);
        Assert.Equal("t-nrg", access.TenantId);
        Assert.False(access.CanSwitch);
    }

    [Fact]
    public void SomebodyInTwoOrganisationsLandsInTheFirstAndMaySwitch()
    {
        var access = OrganisationAccess.Resolve(All, [NlsGroup, NrgGroup], MasterGroup, null, everyoneIsMaster: false);

        Assert.Equal(2, access.Visible.Count);
        Assert.Same(Nrg, access.Current);   // list order, not group order
        Assert.True(access.CanSwitch);

        var switched = OrganisationAccess.Resolve(All, [NlsGroup, NrgGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);
        Assert.Same(Nls, switched.Current);
    }

    [Fact]
    public void SomebodyInNoGroupHasNoAccessAndScopesToNothing()
    {
        // The important case. Signed in, belongs to nothing: the scope must
        // match no row, so a page that forgot to check renders empty rather
        // than rendering everyone's data.
        var access = OrganisationAccess.Resolve(All, ["33333333-3333-3333-3333-333333333333"], MasterGroup, null, everyoneIsMaster: false);

        Assert.False(access.HasAccess);
        Assert.Empty(access.Visible);
        Assert.Null(access.Current);
        Assert.Equal(OrganisationAccess.NoAccessTenantId, access.TenantId);
        Assert.NotNull(access.TenantId);
    }

    [Fact]
    public void AChoiceOutsideWhatIsVisibleIsIgnored()
    {
        // A stale cookie from before somebody was removed from a group.
        var access = OrganisationAccess.Resolve(All, [NrgGroup], MasterGroup, "nextlayersec", everyoneIsMaster: false);

        Assert.Same(Nrg, access.Current);
    }

    [Fact]
    public void AnOrganisationWithNoGroupIsSeenOnlyByTheMaster()
    {
        var employee = OrganisationAccess.Resolve(All, [NrgGroup, NlsGroup], MasterGroup, null, everyoneIsMaster: false);
        Assert.DoesNotContain(Ungrouped, employee.Visible);

        var master = OrganisationAccess.Resolve(All, [MasterGroup], MasterGroup, null, everyoneIsMaster: false);
        Assert.Contains(Ungrouped, master.Visible);
    }

    [Fact]
    public void GroupIdsMatchWhateverTheirCase()
    {
        var access = OrganisationAccess.Resolve(All, [NrgGroup.ToUpperInvariant()], MasterGroup.ToUpperInvariant(), null, everyoneIsMaster: false);

        Assert.Same(Nrg, access.Current);
    }

    [Fact]
    public void NoMasterGroupConfiguredMeansNobodyIsMaster()
    {
        var access = OrganisationAccess.Resolve(All, [MasterGroup], masterGroupId: null, chosenSlug: null, everyoneIsMaster: false);

        Assert.False(access.IsMaster);
        Assert.False(access.HasAccess);
    }
}
