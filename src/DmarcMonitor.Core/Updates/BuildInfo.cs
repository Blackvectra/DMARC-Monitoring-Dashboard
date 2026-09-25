using System.Reflection;

namespace DmarcMonitor.Core.Updates;

/// <summary>
/// Which build this is.
///
/// Stamped at publish time from the tag being released, so a deployed
/// instance can say what it is running and compare that against what has been
/// released since. A build from a working tree has no tag and says so, rather
/// than claiming a version number it does not have - "1.0.0" on a machine
/// running something built from a branch is worse than "development", because
/// it looks like an answer.
/// </summary>
public static class BuildInfo
{
    /// <summary>What a build with no release tag reports.</summary>
    public const string DevelopmentVersion = "development";

    /// <summary>The version, or <see cref="DevelopmentVersion"/>.</summary>
    public static string Version { get; } = Parse(typeof(BuildInfo).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    /// <summary>True when this came from a tagged release rather than a working tree.</summary>
    public static bool IsRelease => !string.Equals(Version, DevelopmentVersion, StringComparison.Ordinal);

    /// <summary>The version an informational version string names.</summary>
    /// <remarks>
    /// An unstamped build says "development" because Directory.Build.props
    /// makes it, not because a number is guessed to be the SDK's default.
    /// That guess was "1.0.0", which is also a version somebody can tag: the
    /// v1.0.0 release would have called itself a development build, shown
    /// that on Settings and Updates, and never been offered an update.
    /// </remarks>
    internal static string Parse(string? informational)
    {
        if (string.IsNullOrWhiteSpace(informational)) { return DevelopmentVersion; }

        // SourceLink appends "+<commit>"; the version is the part before it.
        var version = informational.Split('+')[0].Trim();

        return version.Length == 0 ? DevelopmentVersion : version;
    }
}
