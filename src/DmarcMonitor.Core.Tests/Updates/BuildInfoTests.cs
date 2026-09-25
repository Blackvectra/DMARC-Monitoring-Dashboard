using DmarcMonitor.Core.Updates;

namespace DmarcMonitor.Core.Tests.Updates;

/// <summary>
/// What a build says it is.
///
/// Both directions are a wrong answer on a page somebody trusts: a working
/// tree claiming a version looks up to date with a release it is not, and a
/// release calling itself "development" is never offered an update.
/// </summary>
public sealed class BuildInfoTests
{
    [Theory]
    [InlineData("1.0.0+3f2c9ab", "1.0.0")]
    [InlineData("1.0.0", "1.0.0")]
    [InlineData("1.2.0+3f2c9ab", "1.2.0")]
    [InlineData("1.3.0-rc1+3f2c9ab", "1.3.0-rc1")]
    [InlineData("0.0.0-3f2c9ab+3f2c9ab", "0.0.0-3f2c9ab")]
    public void AStampedBuildReportsItsStamp(string informational, string expected)
    {
        // 1.0.0 is the case that was wrong. It used to be read as the SDK's
        // default, so the v1.0.0 release would have called itself a
        // development build.
        Assert.Equal(expected, BuildInfo.Parse(informational));
    }

    [Theory]
    [InlineData("development+3f2c9ab")]
    [InlineData("development")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("+3f2c9ab")]
    public void AnUnstampedBuildSaysSo(string? informational)
    {
        Assert.Equal(BuildInfo.DevelopmentVersion, BuildInfo.Parse(informational));
    }

    [Fact]
    public void ThisBuildWasNotStampedAndKnowsIt()
    {
        // The tests always run on a build nobody passed a version to, so this
        // proves Directory.Build.props marks one - rather than leaving the
        // SDK's 1.0.0 in place for something else to guess about.
        Assert.Equal(BuildInfo.DevelopmentVersion, BuildInfo.Version);
        Assert.False(BuildInfo.IsRelease);
    }
}
