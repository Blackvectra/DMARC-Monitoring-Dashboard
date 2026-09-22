using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// When a backup problem is worth waking somebody for.
///
/// The distinction is the exit code, and the exit code is the alert: a
/// Breaking finding makes `dmarc health` exit 1, which fails the oneshot unit,
/// which is what OnFailure=dmarc-alert@ hangs off. A Weakness prints and exits
/// 0, so nothing is sent anywhere.
///
/// There was a hole exactly where it mattered. "No backups at all" was
/// Breaking - but install.sh now takes the first copy during the install, so
/// that branch cannot happen on a machine anybody installed. The failure a
/// running install actually develops is the timer stopping and the copies
/// ageing out, and that was a Weakness. The only case left in practice was the
/// only case that did not alert.
/// </summary>
public sealed class HealthCheckBackupTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    private static IReadOnlyList<HygieneFinding> Assess(DateTimeOffset? newestBackup) =>
        HealthCheck.Assess(
            new HealthFacts { BackupDirectory = "/opt/dmarc/backups", LastBackup = newestBackup },
            Now);

    [Fact]
    public void ANightlyBackupThatRanIsNotAFinding() =>
        Assert.Empty(Assess(Now.AddHours(-10)));

    /// <summary>
    /// One missed night is a late job, not a fault. Paging for it is how a
    /// check gets muted, and then the real one arrives into a muted channel.
    /// </summary>
    [Fact]
    public void OneMissedNightPrintsButDoesNotAlert()
    {
        var finding = Assert.Single(Assess(Now.AddHours(-50)));

        Assert.Equal(HygieneSeverity.Weakness, finding.Severity);
        Assert.Contains("2 days old", finding.Problem, StringComparison.Ordinal);
    }

    /// <summary>The one this exists for.</summary>
    [Fact]
    public void AWeekOfMissedNightsIsBackupsHavingStopped()
    {
        var finding = Assert.Single(Assess(Now.AddDays(-9)));

        Assert.Equal(HygieneSeverity.Breaking, finding.Severity);
        Assert.Contains("Backups have stopped", finding.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void NoBackupsAtAllIsStillBreaking()
    {
        var finding = Assert.Single(Assess(null));

        Assert.Equal(HygieneSeverity.Breaking, finding.Severity);
        Assert.Contains("no backups", finding.Problem, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nobody named a directory, so nothing can be concluded. Silence here is
    /// a question that was not asked, not an answer.
    /// </summary>
    [Fact]
    public void SaysNothingWhenNobodyNamedABackupDirectory() =>
        Assert.Empty(HealthCheck.Assess(new HealthFacts { LastBackup = null }, Now));
}
