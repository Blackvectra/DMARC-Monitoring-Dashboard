using System.Globalization;
using DmarcMonitor.Core.Charting;

namespace DmarcMonitor.Core.Tests.Charting;

/// <summary>
/// The arithmetic behind the charts.
///
/// Tested here rather than looked at in a browser because a chart that is
/// subtly wrong looks convincing, which is worse than one that is obviously
/// broken. Every case below is something that would have rendered as a
/// plausible picture of something that did not happen.
/// </summary>
public sealed class ChartTests
{
    private static double?[] Series(params double?[] values) => values;

    // ---- gaps ---------------------------------------------------------------

    [Fact]
    public void TheLineStopsAtAGapRatherThanJoiningAcrossIt()
    {
        // Joining across a day nobody reported on draws a straight line
        // between the days either side, inventing readings never taken.
        var path = Chart.Line(Series(10, null, 10), 100, 50);

        // Two pen-downs: one for each side of the gap.
        Assert.Equal(2, path.Count(c => c == 'M'));
    }

    [Fact]
    public void AGapIsNotDrawnAsZero()
    {
        // The other wrong answer. Plotting an unreported day at zero shows a
        // cliff to the floor and back, and somebody spends an afternoon
        // looking for an outage that never happened.
        var withGap = Chart.Line(Series(10, null, 10), 100, 50);
        var withZero = Chart.Line(Series(10, 0, 10), 100, 50);

        Assert.NotEqual(withZero, withGap);
        Assert.Single(withZero.Where(c => c == 'M'));
    }

    [Fact]
    public void AnAreaIsClosedPerUnbrokenRunRatherThanSpanningAGap()
    {
        // One polygon across a gap shades area under readings that do not
        // exist.
        var path = Chart.Area(Series(10, 20, null, 30, 40), 100, 50);

        Assert.Equal(2, path.Count(c => c == 'Z'));
    }

    [Fact]
    public void ASingleReadingBetweenTwoGapsDrawsNoArea()
    {
        // There is no area under one point, and a one-pixel spike on the
        // baseline reads as data.
        Assert.Equal("", Chart.Area(Series(null, 10, null), 100, 50));
    }

    [Fact]
    public void ASeriesOfNothingButGapsDrawsNothing()
    {
        Assert.Equal("", Chart.Line(Series(null, null, null), 100, 50));
        Assert.Equal("", Chart.Area(Series(null, null, null), 100, 50));
    }

    [Fact]
    public void AnEmptySeriesIsNotAnError()
    {
        // A domain with no window of data at all still renders a page.
        Assert.Equal("", Chart.Line([], 100, 50));
        Assert.Equal("", Chart.Area([], 100, 50));
    }

    // ---- lone readings ------------------------------------------------------

    [Fact]
    public void AReadingWithNoNeighbourIsReportedSoItCanBeDrawnAsADot()
    {
        // Found by looking at the real thing: a domain heard from once in a
        // fortnight produced a path that moves the pen and draws nothing, so
        // the chart was empty and looked identical to having no data at all.
        var dots = Chart.IsolatedPoints(Series(null, 10, null), 100, 50);

        var dot = Assert.Single(dots);
        Assert.Equal(50, dot.X);
    }

    [Fact]
    public void AReadingThatJoinsToAnotherIsNotADot()
    {
        // It is already drawn by the line; a dot on top would be noise.
        Assert.Empty(Chart.IsolatedPoints(Series(10, 20, 30), 100, 50));
    }

    [Fact]
    public void OnlyTheLoneEndOfARunCountsAsIsolated()
    {
        // 10 and 20 join each other; 99 stands alone.
        var dots = Chart.IsolatedPoints(Series(10, 20, null, 99, null), 100, 50);

        Assert.Single(dots);
    }

    [Fact]
    public void ASingleReadingInTheWholeSeriesIsADot()
    {
        Assert.Single(Chart.IsolatedPoints(Series(42), 100, 50));
    }

    [Fact]
    public void NoReadingsMeansNoDots()
    {
        Assert.Empty(Chart.IsolatedPoints(Series(null, null), 100, 50));
        Assert.Empty(Chart.IsolatedPoints([], 100, 50));
    }

    // ---- scale --------------------------------------------------------------

    [Fact]
    public void AnAllZeroSeriesSitsOnTheBaselineRatherThanDividingByZero()
    {
        // A domain that sent nothing all week is a real thing, and NaN in a
        // path attribute renders as an empty chart with no error anywhere.
        var path = Chart.Line(Series(0, 0, 0), 100, 50);

        Assert.DoesNotContain("NaN", path, StringComparison.Ordinal);
        Assert.DoesNotContain("∞", path, StringComparison.Ordinal);
        Assert.Contains("50", path, StringComparison.Ordinal);
    }

    [Fact]
    public void TheTopOfTheScaleCanBeSharedSoTwoChartsCompare()
    {
        // Two charts each scaled to their own maximum look identical however
        // different the numbers are.
        var small = Chart.Line(Series(1), 100, 50, max: 100);
        var large = Chart.Line(Series(100), 100, 50, max: 100);

        Assert.NotEqual(small, large);
    }

    [Fact]
    public void AValueAboveTheGivenMaximumIsClampedRatherThanDrawnOffTheChart()
    {
        var path = Chart.Line(Series(500), 100, 50, max: 100);

        // y=0 is the top edge; anything negative would be drawn outside.
        Assert.DoesNotContain("-", path, StringComparison.Ordinal);
    }

    [Fact]
    public void ASingleReadingSitsInTheMiddleRatherThanAtTheLeftEdge()
    {
        // One reading pinned to x=0 reads as the start of a trend that has not
        // been measured.
        Assert.Equal(50, Chart.X(0, 1, 100));
    }

    [Fact]
    public void TheLastBucketReachesTheRightEdge()
    {
        Assert.Equal(0, Chart.X(0, 5, 100));
        Assert.Equal(100, Chart.X(4, 5, 100));
    }

    // ---- culture ------------------------------------------------------------

    [Fact]
    public void CoordinatesAreWrittenWithADotWhateverTheMachinesLocale()
    {
        // A server set to a locale that writes decimals with a comma emits
        // "12,5 40", which the browser silently refuses to draw: a blank chart
        // on one machine and a correct one on another, nothing in the logs.
        //
        // The separator is overridden directly rather than by naming a culture:
        // this solution builds with InvariantGlobalization, so new
        // CultureInfo("de-DE") throws here and the test would pass for the
        // wrong reason on the very build it is meant to protect.
        var original = Thread.CurrentThread.CurrentCulture;
        try
        {
            var comma = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            comma.NumberFormat.NumberDecimalSeparator = ",";
            Thread.CurrentThread.CurrentCulture = comma;

            // Proves the override actually took, so the assertion below cannot
            // pass merely because the culture change was ignored.
            Assert.Equal("1,5", 1.5.ToString("0.##", CultureInfo.CurrentCulture));

            var path = Chart.Line(Series(1, 2, 3), 10, 7);

            Assert.DoesNotContain(",", path, StringComparison.Ordinal);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = original;
        }
    }

    // ---- the gauge ----------------------------------------------------------

    [Fact]
    public void ASegmentStartsAtTheLeftAndSweepsOverTheTop()
    {
        // The dial runs nine o'clock to three o'clock. A segment from 0 begins
        // at the left edge, level with the center.
        var path = Chart.Arc(cx: 50, cy: 50, outer: 40, inner: 25, from: 0, to: 0.5);

        Assert.StartsWith("M10 50", path, StringComparison.Ordinal);
    }

    [Fact]
    public void AFullDialEndsAtTheRightEdge()
    {
        var path = Chart.Arc(50, 50, 40, 25, 0, 1);

        // 90 is cx + outer: the three o'clock position.
        Assert.Contains("90 50", path, StringComparison.Ordinal);
    }

    [Fact]
    public void ASegmentOfNoWidthIsNotDrawnAtAll()
    {
        // A category with nothing in it must not leave a hairline on the dial,
        // which reads as a category that exists.
        Assert.Equal("", Chart.Arc(50, 50, 40, 25, 0.4, 0.4));
    }

    [Fact]
    public void ADonutSegmentClosesBackAlongTheInnerEdge()
    {
        var path = Chart.Arc(50, 50, 40, 25, 0, 0.5);

        // Two arcs: out along the rim, back along the inside.
        Assert.Equal(2, path.Count(c => c == 'A'));
        Assert.EndsWith("Z", path, StringComparison.Ordinal);
    }

    [Fact]
    public void AZeroInnerRadiusGivesAPieSliceThroughTheCentre()
    {
        var path = Chart.Arc(50, 50, 40, 0, 0, 0.5);

        Assert.Single(path.Where(c => c == 'A'));
        Assert.Contains("L50 50", path, StringComparison.Ordinal);
    }

    [Fact]
    public void ASegmentOverHalfTheDialSetsTheLargeArcFlag()
    {
        // Without it the browser draws the short way round, which renders the
        // largest category as the smallest.
        var big = Chart.Arc(50, 50, 40, 25, 0, 0.9);
        var small = Chart.Arc(50, 50, 40, 25, 0, 0.3);

        Assert.Contains("0 1 1", big, StringComparison.Ordinal);
        Assert.Contains("0 0 1", small, StringComparison.Ordinal);
    }

    [Fact]
    public void FractionsOutsideTheDialAreClampedRatherThanDrawnOffIt()
    {
        var path = Chart.Arc(50, 50, 40, 25, -0.5, 1.5);

        Assert.DoesNotContain("NaN", path, StringComparison.Ordinal);
        Assert.StartsWith("M10 50", path, StringComparison.Ordinal);
    }

    [Fact]
    public void ADialOfNoSizeDrawsNothing()
    {
        Assert.Equal("", Chart.Arc(50, 50, 0, 0, 0, 1));
    }

    [Fact]
    public void GaugeCoordinatesAreWrittenWithADotWhateverTheLocale()
    {
        var original = Thread.CurrentThread.CurrentCulture;
        try
        {
            var comma = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            comma.NumberFormat.NumberDecimalSeparator = ",";
            Thread.CurrentThread.CurrentCulture = comma;

            Assert.Equal("1,5", 1.5.ToString("0.##", CultureInfo.CurrentCulture));
            Assert.DoesNotContain(",", Chart.Arc(50, 50, 40, 25, 0.13, 0.67), StringComparison.Ordinal);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = original;
        }
    }

    // ---- shares written for a reader ---------------------------------------

    [Theory]
    [InlineData(159, 16_249 + 1_477 + 159, "<1%")]
    [InlineData(1_477, 16_249 + 1_477 + 159, "8%")]
    [InlineData(16_249, 16_249 + 1_477 + 159, "91%")]
    public void ASharePrintsTheWayAReaderExpects(long value, long total, string expected)
    {
        Assert.Equal(expected, Chart.Share(value, total));
    }

    [Fact]
    public void ATinyShareIsNeverPrintedAsNone()
    {
        // A hundred and fifty-nine threatening messages is the finding, not
        // the rounding error. "0%" reads as "none", which is the one thing it
        // is not.
        Assert.Equal("<1%", Chart.Share(1, 100_000));
    }

    [Fact]
    public void AShareShortOfEverythingIsNotPrintedAsEverything()
    {
        // 99.6% rounds to 100%, which tells somebody every message was fine
        // while some were not.
        Assert.Equal(">99%", Chart.Share(9_996, 10_000));
    }

    [Fact]
    public void EverythingIsPrintedAsEverything()
    {
        Assert.Equal("100%", Chart.Share(50, 50));
    }

    [Fact]
    public void NothingAtAllIsZero()
    {
        Assert.Equal("0%", Chart.Share(0, 100));
        Assert.Equal("0%", Chart.Share(5, 0));
    }

    // ---- proportions --------------------------------------------------------

    [Fact]
    public void SlicesSumToExactlyOneHundred()
    {
        // Three equal thirds round to 33.3 each and leave a hairline gap at
        // the end of the bar.
        var placed = Chart.Stack([
            new Slice("a", 1, "one"),
            new Slice("b", 1, "two"),
            new Slice("c", 1, "three"),
        ]);

        Assert.Equal(100.0, placed.Sum(p => p.Percent), 3);
    }

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(1, 2, 3)]
    [InlineData(7, 11, 13)]
    [InlineData(1, 1, 99_998)]
    [InlineData(999_999, 1, 1)]
    public void SlicesSumToOneHundredForAnyMixture(long a, long b, long c)
    {
        var placed = Chart.Stack([
            new Slice("a", a, "one"),
            new Slice("b", b, "two"),
            new Slice("c", c, "three"),
        ]);

        Assert.Equal(100.0, placed.Sum(p => p.Percent), 3);
    }

    [Fact]
    public void EachSliceStartsWhereTheLastOneEnded()
    {
        var placed = Chart.Stack([
            new Slice("a", 50, "one"),
            new Slice("b", 30, "two"),
            new Slice("c", 20, "three"),
        ]);

        Assert.Equal(0, placed[0].Offset);
        Assert.Equal(placed[0].Percent, placed[1].Offset, 3);
        Assert.Equal(placed[0].Percent + placed[1].Percent, placed[2].Offset, 3);
    }

    [Fact]
    public void SomethingThatDidNotHappenGetsNoSegmentAndNoLegendEntry()
    {
        var placed = Chart.Stack([
            new Slice("delivered", 10, "one"),
            new Slice("quarantined", 0, "two"),
            new Slice("rejected", 5, "three"),
        ]);

        Assert.Equal(2, placed.Count);
        Assert.DoesNotContain(placed, p => p.Slice.Label == "quarantined");
    }

    [Fact]
    public void NothingAtAllProducesNoSegments()
    {
        // Rather than one full-width slice of nothing, which is what a naive
        // division by a zero total produces.
        Assert.Empty(Chart.Stack([new Slice("a", 0, "one"), new Slice("b", 0, "two")]));
        Assert.Empty(Chart.Stack([]));
    }

    [Fact]
    public void ASingleSliceFillsTheBar()
    {
        var placed = Assert.Single(Chart.Stack([new Slice("all", 42, "one")]));

        Assert.Equal(100.0, placed.Percent, 3);
        Assert.Equal(0, placed.Offset);
    }

    [Fact]
    public void AVanishinglySmallSliceIsStillCountedRatherThanRoundedAway()
    {
        // One rejected message in a hundred thousand is the finding, not the
        // rounding error. It may render as a sliver, but it must not vanish
        // from the legend.
        var placed = Chart.Stack([
            new Slice("delivered", 100_000, "one"),
            new Slice("rejected", 1, "two"),
        ]);

        Assert.Equal(2, placed.Count);
        Assert.Equal(1, placed.Count(p => p.Slice.Label == "rejected"));
    }
}
