using System.Security.Claims;
using DmarcMonitor.Web.Auth;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The marker Entra sends in place of a group list that would not fit in the
/// token.
///
/// This app signs in with the ID-token flow, for which Microsoft stops listing
/// groups above a handful. A person in more groups than that reaches the app
/// with no groups at all, which is indistinguishable, unless something looks,
/// from never having been added to any.
/// </summary>
public sealed class GroupsClaimTests
{
    private static ClaimsPrincipal Person(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "Test"));

    [Fact]
    public void TheImplicitFlowMarkerMeansTheGroupsWereLeftOut() =>
        Assert.True(OrgContext.GroupsOmitted(Person(new Claim("hasgroups", "true"))));

    [Fact]
    public void TheOverageSourceNamingGroupsMeansTheGroupsWereLeftOut() =>
        Assert.True(OrgContext.GroupsOmitted(Person(new Claim("_claim_names", """{"groups":"src1"}"""))));

    [Fact]
    public void AnOverageSourceForSomethingElseIsNotEvidence() =>
        Assert.False(OrgContext.GroupsOmitted(Person(new Claim("_claim_names", """{"roles":"src1"}"""))));

    [Theory]
    [InlineData("false")]
    [InlineData("yes")]
    [InlineData("")]
    public void OnlyTrueCountsAsTheMarker(string value) =>
        Assert.False(OrgContext.GroupsOmitted(Person(new Claim("hasgroups", value))));

    [Theory]
    [InlineData("not json")]
    [InlineData("""["groups"]""")]
    [InlineData("")]
    public void ANamesClaimThatIsNotTheShapeEntraSendsIsNotEvidence(string value) =>
        Assert.False(OrgContext.GroupsOmitted(Person(new Claim("_claim_names", value))));

    [Fact]
    public void NoMarkerMeansNothingWasLeftOut() =>
        Assert.False(OrgContext.GroupsOmitted(Person(new Claim(ClaimTypes.Name, "operator@example.com"))));

    [Theory]
    [InlineData("groups")]
    [InlineData("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")]
    public void AGroupThatIsListedMeansNothingWasLeftOut(string claimType) =>
        Assert.False(OrgContext.GroupsOmitted(Person(
            new Claim(claimType, "11111111-1111-1111-1111-111111111111"),
            new Claim("hasgroups", "true"))));
}
