using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Noticing that this install has stopped working.
///
/// Every finding here tells an operator something is broken, and every one is
/// read at the end of a day rather than the start. So the rules that matter
/// most are the ones about staying QUIET: a check that cries wolf on an
/// ordinary Monday is a check somebody mutes, and then the real one arrives
/// into a muted channel.
/// </summary>
public sealed class HealthCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    /// <param name="neverCollected">
    /// Distinct from leaving <paramref name="lastStored"/> unset, which means
    /// "an ordinary healthy install". Null alone cannot say "never", because
    /// the helper cannot tell it from a caller who did not care.
    /// </param>
    private static HealthFacts Facts(
        DateTimeOffset? lastStored = null,
        bool neverCollected = false,
        int domains = 17,
        int storedLastDay = 40,
        string org = "local",
        IReadOnlyList<QuietDomain>? quiet = null,
        string? backupDir = null,
        DateTimeOffset? lastBackup = null,
        IReadOnlyList<string>? heldTwice = null) => new()
        {
            Collection =
            [
                new CollectionFacts(
                    org, domains,
                    neverCollected ? null : lastStored ?? Now.AddHours(-2),
                    storedLastDay)
            ],
            Quiet = quiet ?? [],
            BackupDirectory = backupDir,
            LastBackup = lastBackup,
            HeldTwice = heldTwice ?? [],
        };

    private static IReadOnlyList<HygieneFinding> Assess(HealthFacts facts) =>
        HealthCheck.Assess(facts, Now);

    // ---- collection ------------------------------------------------------------

    [Fact]
    public void AnInstallCollectingNormallySaysNothing()
    {
        Assert.Empty(Assess(Facts()));
    }

    [Fact]
    public void CollectionThatHasStoppedIsBreaking()
    {
        var f = Assert.Single(Assess(Facts(lastStored: Now.AddDays(-3))));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("3 days", f.Problem, StringComparison.Ordinal);
        Assert.Contains("journalctl", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AQuietNightIsNotAStoppedCollector()
    {
        // Receivers send at most daily and mostly overnight. A check that
        // fires after a few quiet hours fires most mornings.
        Assert.Empty(Assess(Facts(lastStored: Now.AddHours(-20))));
    }

    [Theory]
    [InlineData(35, false)]
    [InlineData(37, true)]
    public void TheThresholdIsCheckedFromBothSides(int hoursAgo, bool expectFinding)
    {
        // A boundary only tested from the failing side is a boundary that can
        // drift into firing every day without a test noticing.
        var findings = Assess(Facts(lastStored: Now.AddHours(-hoursAgo)));

        Assert.Equal(expectFinding, findings.Count > 0);
    }

    [Fact]
    public void EachOrganizationIsJudgedOnItsOwn()
    {
        // The failure this exists to catch. Two collectors break
        // independently, and one still working keeps an install-wide figure
        // looking healthy while a whole customer book goes dark.
        var facts = new HealthFacts
        {
            Collection =
            [
                new CollectionFacts("nrg", 17, Now.AddHours(-1), 40),
                new CollectionFacts("nextlayersec", 2, Now.AddDays(-5), 0),
            ],
        };

        var f = Assert.Single(Assess(facts));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("nextlayersec", f.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain("nrg", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrganizationThatHasNeverCollectedIsAWeaknessNotABreak()
    {
        // Nothing has broken - it has never worked, which is an onboarding
        // question and needs a different answer.
        var f = Assert.Single(Assess(Facts(neverCollected: true)));

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("no report has ever been stored", f.Problem, StringComparison.Ordinal);
        Assert.Contains("reachability", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrganizationWithNoDomainsAndNoReportsIsNotAFault()
    {
        // An organization created and not yet used has nothing to collect, so
        // its silence means nothing.
        Assert.Empty(Assess(Facts(neverCollected: true, domains: 0)));
    }

    // ---- domains that went quiet -------------------------------------------------

    [Fact]
    public void ADomainThatStoppedBeingReportedOnIsNamed()
    {
        var quiet = new[] { new QuietDomain("acme.com", Now.AddDays(-30), 140) };
        var f = Assert.Single(Assess(Facts(quiet: quiet)));

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("acme.com", f.Problem, StringComparison.Ordinal);
        Assert.Contains("no data", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void QuietDomainsAreNotListedWhenCollectionItselfIsBroken()
    {
        // If nothing is being stored at all then every domain is quiet, and
        // saying so seventeen times buries the one finding that matters.
        var quiet = new[]
        {
            new QuietDomain("a.example", Now.AddDays(-30), 10),
            new QuietDomain("b.example", Now.AddDays(-30), 10),
        };

        var f = Assert.Single(Assess(Facts(lastStored: Now.AddDays(-3), quiet: quiet)));

        Assert.Equal("collection", f.Record);
    }

    [Fact]
    public void ALongListOfQuietDomainsIsSummarizedRatherThanPrinted()
    {
        var quiet = Enumerable.Range(0, 9)
            .Select(i => new QuietDomain($"d{i}.example", Now.AddDays(-30), 5))
            .ToList();

        var f = Assert.Single(Assess(Facts(quiet: quiet)));

        Assert.Contains("9 domains", f.Problem, StringComparison.Ordinal);
        Assert.Contains("and 4 more", f.Problem, StringComparison.Ordinal);
    }

    // ---- backups -----------------------------------------------------------------

    [Fact]
    public void NothingIsSaidAboutBackupsWhenNobodyAskedAboutThem()
    {
        // An absent answer to a question never put is not a finding. Reporting
        // "no backups" for an operator who never named a directory would be a
        // sentence about something nobody established.
        Assert.Empty(Assess(Facts(backupDir: null, lastBackup: null)));
    }

    [Fact]
    public void ADirectoryWithNoBackupsInItIsBreaking()
    {
        var f = Assert.Single(Assess(Facts(backupDir: "/var/backups/dmarc", lastBackup: null)));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("/var/backups/dmarc", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ARecentBackupSaysNothing()
    {
        Assert.Empty(Assess(Facts(backupDir: "/b", lastBackup: Now.AddHours(-10))));
    }

    [Fact]
    public void AStaleBackupIsAWeakness()
    {
        var f = Assert.Single(Assess(Facts(backupDir: "/b", lastBackup: Now.AddDays(-4))));

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("4 days old", f.Problem, StringComparison.Ordinal);
    }

    // ---- a domain in two organizations ---------------------------------------------

    [Fact]
    public void ADomainHeldTwiceIsReportedWithoutBeingJudged()
    {
        // Two MSPs sharing a name is legitimate and a mistyped --org looks
        // identical. The confident version of this finding tells somebody to
        // delete another customer's domain.
        var f = Assert.Single(Assess(Facts(heldTwice: ["example.com"])));

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("example.com", f.Problem, StringComparison.Ordinal);
        Assert.Contains("legitimate", f.Problem, StringComparison.Ordinal);
    }

    // ---- ordering and shape ----------------------------------------------------------

    [Fact]
    public void TheWorstFindingComesFirst()
    {
        var facts = Facts(
            lastStored: Now.AddDays(-3),          // breaking
            backupDir: "/b", lastBackup: Now.AddDays(-4),   // weakness
            heldTwice: ["example.com"]);                    // weakness

        var findings = Assess(facts);

        Assert.True(findings.Count >= 2);
        Assert.Equal(HygieneSeverity.Breaking, findings[0].Severity);
        Assert.Equal(findings.OrderByDescending(f => f.Severity).Select(f => f.Severity),
                     findings.Select(f => f.Severity));
    }

    [Fact]
    public void EveryFindingSaysWhatToDo()
    {
        // A finding without a fix is an alarm, not a check.
        var facts = Facts(lastStored: Now.AddDays(-3), backupDir: "/b", heldTwice: ["a.example"]);

        Assert.All(Assess(facts), f =>
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Problem));
            Assert.False(string.IsNullOrWhiteSpace(f.Fix));
            Assert.False(string.IsNullOrWhiteSpace(f.Record));
        });
    }

    [Fact]
    public void NullsAreRefused()
    {
        Assert.Throws<ArgumentNullException>(() => HealthCheck.Assess(null!, Now));
    }
}
