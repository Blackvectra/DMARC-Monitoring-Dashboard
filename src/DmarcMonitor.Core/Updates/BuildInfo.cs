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
    public static string Version { get; } = Read();

    /// <summary>True when this came from a tagged release rather than a working tree.</summary>
    public static bool IsRelease => !string.Equals(Version, DevelopmentVersion, StringComparison.Ordinal);

    private static string Read()
    {
        var informational = typeof(BuildInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        if (string.IsNullOrWhiteSpace(informational)) { return DevelopmentVersion; }

        // SourceLink appends "+<commit>"; the version is the part before it.
        var version = informational.Split('+')[0].Trim();

        // The SDK's default when nothing was passed. Treating it as a real
        // version would have a development build believe it is up to date
        // with a release, or behind one, on no evidence at all.
        return version is "" or "1.0.0" ? DevelopmentVersion : version;
    }
}
