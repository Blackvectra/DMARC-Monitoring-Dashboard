namespace DmarcMonitor.Core.Tests;

/// <summary>
/// The front door has to describe what is behind it.
///
/// It did not. The README described a Windows WPF desktop dashboard storing
/// its configuration in the Windows Registry, and told a new reader to run
/// Install-DMARCMonitor.ps1 first. What this repository actually releases is a
/// Blazor Server web app deployed to Linux through systemd and a
/// cross-platform CLI - a different product, on a different platform, with a
/// different configuration model and a different install path. There was not
/// one mention of .NET, the web app, or docs/DEPLOYING.md anywhere in it.
///
/// Nobody notices this from inside the code. It is only ever met by somebody
/// arriving at the repository for the first time, which by then includes
/// whoever comes back to it in six months.
/// </summary>
public sealed class DocumentationTests
{
    /// <summary>
    /// Walks up from the test binary to the directory holding the solution.
    /// </summary>
    /// <remarks>
    /// The test runner's working directory is somewhere under bin/, and how
    /// deep depends on the configuration and framework, so the root is found
    /// by looking for a landmark rather than by counting "..".
    /// </remarks>
    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "README.md")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!;
    }

    private static string Readme() => File.ReadAllText(Path.Combine(RepoRoot().FullName, "README.md"));

    [Theory]
    [InlineData("docs/RUNNING.md")]
    [InlineData("docs/DEPLOYING.md")]
    [InlineData("docs/INGEST-SETUP.md")]
    public void TheReadmePointsAtTheDocumentationForWhatShips(string doc)
    {
        Assert.Contains(doc, Readme(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheDocumentationItPointsAtExists()
    {
        // A front door linking to a page that is not there is worse than one
        // linking nowhere.
        var root = RepoRoot().FullName;

        foreach (var doc in new[] { "docs/RUNNING.md", "docs/DEPLOYING.md", "docs/INGEST-SETUP.md", "docs/OPEN-ISSUES.md" })
        {
            Assert.True(File.Exists(Path.Combine(root, doc.Replace('/', Path.DirectorySeparatorChar))),
                $"README links to {doc}, which does not exist");
        }
    }

    [Fact]
    public void TheReadmeDescribesTheApplicationThatIsActuallyReleased()
    {
        var readme = Readme();

        // The two things release.yml publishes.
        Assert.Contains("dmarc", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("web app", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(".NET", readme, StringComparison.Ordinal);
    }

    [Fact]
    public void TheReadmeDoesNotTellANewReaderToInstallTheSupersededProduct()
    {
        // It is fine to mention the PowerShell - it is still in the tree and
        // still tested - but not as the thing to run first.
        var readme = Readme();

        var install = readme.IndexOf("Install-DMARCMonitor.ps1", StringComparison.Ordinal);
        if (install < 0) { return; }

        // Where it does appear, it must be under the heading that says so.
        var superseded = readme.IndexOf("superseded", StringComparison.OrdinalIgnoreCase);
        Assert.True(superseded >= 0 && superseded < install,
            "Install-DMARCMonitor.ps1 is named before anything says the PowerShell is superseded");
    }

    [Fact]
    public void NothingInTheShippedCodeOrDeployCallsAPowerShellScript()
    {
        // The claim the README now makes, checked rather than asserted. If
        // this ever fails, the PowerShell is load-bearing again and the README
        // is wrong the other way round.
        var root = RepoRoot().FullName;
        var offenders = new List<string>();

        // The shipped projects and the deploy scripts. Test projects are
        // excluded because they are not shipped - and because this very file
        // names a .ps1 in the message above, which made the first run of it
        // fail on itself.
        foreach (var dir in new[]
                 {
                     Path.Combine("src", "DmarcMonitor.Core"),
                     Path.Combine("src", "DmarcMonitor.Cli"),
                     Path.Combine("src", "DmarcMonitor.Web"),
                     "deploy",
                 })
        {
            var path = Path.Combine(root, dir);
            if (!Directory.Exists(path)) { continue; }

            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                    || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                {
                    continue;
                }

                if (Path.GetExtension(file) is not (".cs" or ".razor" or ".sh" or ".service" or ".path" or ".json")) { continue; }

                if (File.ReadAllText(file).Contains(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add(Path.GetRelativePath(root, file));
                }
            }
        }

        Assert.True(offenders.Count == 0, $"these reference a PowerShell script: {string.Join(", ", offenders)}");
    }
}
