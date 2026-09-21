using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// The retention window, and the only thing in this product that deletes a
/// customer's history.
///
/// The schema has assumed a window since it was written - it sizes
/// aggregate_records at "~22M rows at 90-day retention" - and nothing ever
/// enforced one, so both report tables grew without bound. Beyond disk that
/// matters most for the forensic table, which holds real message headers:
/// subject lines, message ids, the headers of somebody's mail. Keeping those
/// indefinitely turns a monitoring tool into a mail archive nobody agreed to.
///
/// Most of what follows is about refusing a policy rather than applying one.
/// This is the operation where a clamped or silently-adjusted setting is not a
/// small difference.
/// </summary>
public sealed class RetentionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 21, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheDefaultKeepsThirteenMonthsOfCountsAndOneOfHeaders()
    {
        var policy = new RetentionPolicy();

        Assert.Equal(400, policy.AggregateDays);
        Assert.Equal(30, policy.ForensicDays);
        Assert.True(policy.IsValid);
    }

    [Fact]
    public void ThirteenMonthsIsDeliberateSoThisMonthHasLastYearsBesideIt()
    {
        // Twelve exactly means the year-on-year comparison is gone the day it
        // is wanted, which is the day somebody writes the annual report.
        Assert.True(new RetentionPolicy().AggregateDays > 365);
    }

    [Fact]
    public void ForensicDataIsNeverTheThingKeptLongest()
    {
        // It is the only class here holding other people's message content.
        var policy = new RetentionPolicy { AggregateDays = 90, ForensicDays = 365 };

        Assert.False(policy.IsValid);
        Assert.Contains(policy.Problems, p => p.Contains("never be the thing kept longest", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(6)]
    public void AWindowShorterThanAWeekIsRefused(int days)
    {
        // Receivers report on a day's mail a day or two later. A shorter
        // window deletes reports about mail that is still arriving, and the
        // domain reads as quiet.
        var policy = new RetentionPolicy { AggregateDays = days };

        Assert.False(policy.IsValid);
        Assert.Contains(policy.Problems, p => p.Contains("still arriving", StringComparison.Ordinal));
    }

    [Fact]
    public void ACutoffIsTheDatabasesOwnDateFormat()
    {
        // A cutoff compared as a string against stored dates has to be spelled
        // the same way they are, or it silently matches nothing - or
        // everything.
        Assert.Equal("2026-08-22 12:00:00", new RetentionPolicy { AggregateDays = 30 }.AggregateCutoff(Now));
    }

    [Fact]
    public void TheTwoClassesGetDifferentCutoffs()
    {
        var policy = new RetentionPolicy { AggregateDays = 400, ForensicDays = 30 };

        Assert.NotEqual(policy.AggregateCutoff(Now), policy.ForensicCutoff(Now));
        Assert.True(string.CompareOrdinal(policy.AggregateCutoff(Now), policy.ForensicCutoff(Now)) < 0);
    }

    [Fact]
    public void APolicyReadsAsOneLineForALogOrAPage()
    {
        Assert.Equal("aggregate 400 days, forensic 30 days", new RetentionPolicy().ToString());
    }

    // ---- what a run reports ------------------------------------------------------

    [Fact]
    public void ADryRunSaysWhatItWouldRemoveRatherThanWhatItDid()
    {
        var result = new PruneResult(12, 3400, 5, 2, Applied: false);

        Assert.StartsWith("would remove", result.Describe(), StringComparison.Ordinal);
        Assert.Contains("3,400 row(s)", result.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void AnAppliedRunSaysWhatItRemoved()
    {
        Assert.StartsWith("removed", new PruneResult(12, 3400, 5, 2, Applied: true).Describe(),
            StringComparison.Ordinal);
    }

    [Fact]
    public void NothingOldEnoughIsSaidPlainlyRatherThanAsAListOfZeroes()
    {
        var result = new PruneResult(0, 0, 0, 0, Applied: true);

        Assert.True(result.NothingToDo);
        Assert.Equal("nothing is old enough to remove", result.Describe());
    }

    [Fact]
    public void TheTotalCountsReportsRatherThanRows()
    {
        // The rows inside an aggregate report are not separate things an
        // operator deleted; counting them in the total would make one report
        // read as thousands.
        Assert.Equal(19, new PruneResult(12, 3400, 5, 2, Applied: true).Total);
    }
}
