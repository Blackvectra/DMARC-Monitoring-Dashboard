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

                // deploy/bootstrap.ps1 is not the superseded product: it is the
                // Windows counterpart of bootstrap.sh, shipped on purpose and
                // run in CI on a Windows runner. Naming it is fine; naming any
                // other .ps1 is the old product creeping back.
                var text = File.ReadAllText(file).Replace("bootstrap.ps1", "", StringComparison.OrdinalIgnoreCase);
                if (text.Contains(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add(Path.GetRelativePath(root, file));
                }
            }
        }

        Assert.True(offenders.Count == 0, $"these reference a PowerShell script: {string.Join(", ", offenders)}");
    }

    // The deployment path. DEPLOYING.md tells somebody to run scripts and
    // rely on units; these hold the tree to what it says, because the server
    // has no checkout and finds out the hard way.

    [Fact]
    public void TheDeployDirectoryShipsEverythingTheDocsTellSomebodyToRun()
    {
        var root = RepoRoot().FullName;

        foreach (var name in new[]
                 {
                     "bootstrap.sh", "bootstrap.ps1",
                     "install.sh", "update.sh", "rollback.sh", "install-update-agent.sh", "update-agent.sh",
                     "dmarc-web.service", "dmarc-ingest.service", "dmarc-ingest.timer",
                     "dmarc-update.service", "dmarc-update.path",
                 })
        {
            Assert.True(File.Exists(Path.Combine(root, "deploy", name)), $"deploy/{name} is missing");
        }

        // And the server gets them: they must travel with the release, and
        // the doc must say where they came from.
        var release = File.ReadAllText(Path.Combine(root, ".github", "workflows", "release.yml"));
        var deploying = File.ReadAllText(Path.Combine(root, "docs", "DEPLOYING.md"));
        Assert.Contains("dmarc-deploy.tar.gz", release, StringComparison.Ordinal);
        Assert.Contains("dmarc-deploy.tar.gz", deploying, StringComparison.Ordinal);
    }

    [Fact]
    public void TheWebUnitListensOnLoopbackAndIsSandboxed()
    {
        // Loopback is what makes a firewall mistake survivable; the sandbox
        // is what makes a compromised web app a smaller thing. Both are one
        // deleted line from gone.
        var unit = File.ReadAllText(Path.Combine(RepoRoot().FullName, "deploy", "dmarc-web.service"));

        Assert.Contains("ASPNETCORE_URLS=http://127.0.0.1:5000", unit, StringComparison.Ordinal);
        Assert.Contains("ProtectSystem=strict", unit, StringComparison.Ordinal);
        Assert.Contains("ProtectHome=true", unit, StringComparison.Ordinal);
        Assert.Contains("ReadWritePaths=/opt/dmarc/data", unit, StringComparison.Ordinal);
    }

    [Fact]
    public void TheIngestUnitGivesTheSingleFileBinarySomewhereToUnpack()
    {
        // With the home directory hidden and nothing else said, the binary
        // exits 159 before printing a word. The unit has to say where.
        var unit = File.ReadAllText(Path.Combine(RepoRoot().FullName, "deploy", "dmarc-ingest.service"));

        Assert.Contains("ProtectHome=true", unit, StringComparison.Ordinal);
        Assert.Contains("DOTNET_BUNDLE_EXTRACT_BASE_DIR=/opt/dmarc/data/.net", unit, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Ubuntu 24.04")]
    [InlineData("Amazon Linux 2023")]
    [InlineData("deploy/install.sh")]
    [InlineData("deploy/bootstrap.sh")]
    [InlineData("bootstrap.ps1")]
    [InlineData("DOTNET_BUNDLE_EXTRACT_BASE_DIR")]
    [InlineData("signout-callback-oidc")]
    [InlineData("ID tokens")]
    [InlineData("Auth:MasterGroupId")]
    [InlineData("groups claim")]
    public void DeployingCoversBothDistributionsAndTheInstaller(string phrase)
    {
        var deploying = File.ReadAllText(Path.Combine(RepoRoot().FullName, "docs", "DEPLOYING.md"));

        Assert.Contains(phrase, deploying, StringComparison.Ordinal);
    }

    [Fact]
    public void NoDocumentedCommandHandsTheServiceAccountSomebodyElsesHome()
    {
        // `sudo -E -u dmarc` keeps the caller's HOME, so the single-file
        // binary tries to unpack under /root as the dmarc account and exits
        // 159 before printing anything. The doc shipped exactly that command
        // once, directly above the paragraph explaining the symptom. -H is
        // what makes -E safe here.
        var root = RepoRoot().FullName;

        foreach (var doc in new[] { "docs/DEPLOYING.md", "docs/RUNNING.md", "docs/INGEST-SETUP.md", "README.md" })
        {
            var lines = File.ReadAllLines(Path.Combine(root, doc.Replace('/', Path.DirectorySeparatorChar)));
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains("sudo -E", StringComparison.Ordinal)
                    && lines[i].Contains("-u ", StringComparison.Ordinal)
                    && !lines[i].Contains("-H", StringComparison.Ordinal))
                {
                    Assert.Fail($"{doc}:{i + 1} runs a command as another user with -E but without -H: {lines[i].Trim()}");
                }
            }
        }
    }
}
