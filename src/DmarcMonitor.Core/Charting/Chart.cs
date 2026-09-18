using System.Globalization;
using System.Text;

namespace DmarcMonitor.Core.Charting;

/// <summary>One slice of a proportion bar or donut.</summary>
/// <param name="Label">What it is, spelled out. Never only a colour.</param>
/// <param name="Value">The count.</param>
/// <param name="Css">The class carrying its colour.</param>
public sealed record Slice(string Label, long Value, string Css);

/// <summary>A slice with its geometry worked out.</summary>
public sealed record PlacedSlice(Slice Slice, double Percent, double Offset);

/// <summary>
/// The arithmetic behind the charts, kept away from the markup.
/// </summary>
/// <remarks>
/// <para>
/// Server-rendered SVG rather than a charting library. This product is
/// installed on somebody's own server, often one that cannot reach the
/// internet, so a chart that fetches a script from a CDN is a chart that does
/// not draw. The client report is also an HTML document that gets mailed and
/// printed, where no script runs at all; inline SVG survives both.
/// </para>
/// <para>
/// The geometry lives here, in Core, because it is arithmetic and arithmetic
/// can be tested. Worked out inside a .razor file it could only ever be
/// checked by looking at it, and a chart that is subtly wrong looks
/// convincing - which is worse than one that is obviously broken.
/// </para>
/// </remarks>
public static class Chart
{
    /// <summary>
    /// Builds an SVG path through a series, lifting the pen across gaps.
    /// </summary>
    /// <remarks>
    /// A null is a day nobody reported on. Joining across it draws a straight
    /// line between the days either side, which invents readings that were
    /// never taken; plotting it as zero draws a cliff to the floor and back,
    /// which invents an outage. Neither is honest, so the line simply stops
    /// and starts again.
    /// </remarks>
    /// <param name="values">One per bucket, null where nothing is known.</param>
    /// <param name="width">Width of the plotting area in user units.</param>
    /// <param name="height">Height of the plotting area in user units.</param>
    /// <param name="max">
    /// Top of the scale. Defaults to the largest value present. Pass it
    /// explicitly to hold two charts to one scale.
    /// </param>
    public static string Line(IReadOnlyList<double?> values, double width, double height, double? max = null)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0) { return ""; }

        var top = Top(values, max);
        var path = new StringBuilder();
        var penDown = false;

        for (var i = 0; i < values.Count; i++)
        {
            if (values[i] is not { } value)
            {
                penDown = false;
                continue;
            }

            var x = X(i, values.Count, width);
            var y = Y(value, top, height);

            path.Append(penDown ? 'L' : 'M')
                .Append(N(x)).Append(' ').Append(N(y)).Append(' ');
            penDown = true;
        }

        return path.ToString().TrimEnd();
    }

    /// <summary>
    /// The same series as a filled shape, one closed region per unbroken run.
    /// </summary>
    /// <remarks>
    /// Separate regions rather than one polygon, for the same reason the line
    /// breaks: a single fill spanning a gap shades area under readings that do
    /// not exist.
    /// </remarks>
    public static string Area(IReadOnlyList<double?> values, double width, double height, double? max = null)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0) { return ""; }

        var top = Top(values, max);
        var path = new StringBuilder();
        var run = new List<(double X, double Y)>();

        void Close()
        {
            // A single point has no area. Drawing it would put a one-pixel
            // spike on the baseline that reads as data.
            if (run.Count < 2) { run.Clear(); return; }

            path.Append('M').Append(N(run[0].X)).Append(' ').Append(N(height)).Append(' ');
            foreach (var (x, y) in run)
            {
                path.Append('L').Append(N(x)).Append(' ').Append(N(y)).Append(' ');
            }
            path.Append('L').Append(N(run[^1].X)).Append(' ').Append(N(height)).Append(" Z ");
            run.Clear();
        }

        for (var i = 0; i < values.Count; i++)
        {
            if (values[i] is not { } value) { Close(); continue; }
            run.Add((X(i, values.Count, width), Y(value, top, height)));
        }
        Close();

        return path.ToString().TrimEnd();
    }

    /// <summary>
    /// Turns counts into percentages that sum to exactly 100.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rounding each slice independently leaves a bar that stops at 99.8% or
    /// overruns to 100.2%, and on a stacked bar that shows as a hairline gap
    /// or an overlap at the end. The largest remainder absorbs the difference,
    /// which is the standard apportionment and keeps every slice within half a
    /// point of its true share.
    /// </para>
    /// <para>
    /// Zero-valued slices are dropped: a legend entry for something that did
    /// not happen is noise, and a zero-width segment is an invisible one that
    /// still takes a colour out of the palette.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<PlacedSlice> Stack(IEnumerable<Slice> slices)
    {
        ArgumentNullException.ThrowIfNull(slices);

        var present = slices.Where(s => s.Value > 0).ToList();
        if (present.Count == 0) { return []; }

        var total = present.Sum(s => s.Value);

        // Held to one decimal place, matching how percentages are written
        // everywhere else in this product.
        var exact = present.Select(s => s.Value * 1000.0 / total).ToList();
        var rounded = exact.Select(e => Math.Floor(e)).ToList();

        var shortfall = (int)Math.Round(1000 - rounded.Sum(), MidpointRounding.AwayFromZero);
        var order = Enumerable.Range(0, present.Count)
            .OrderByDescending(i => exact[i] - rounded[i])
            .ThenBy(i => i)
            .ToList();

        for (var n = 0; n < shortfall; n++)
        {
            rounded[order[n % order.Count]] += 1;
        }

        var placed = new List<PlacedSlice>(present.Count);
        var offset = 0.0;
        for (var i = 0; i < present.Count; i++)
        {
            var percent = rounded[i] / 10.0;
            placed.Add(new PlacedSlice(present[i], percent, offset));
            offset += percent;
        }

        return placed;
    }

    /// <summary>
    /// Readings with no neighbour to join to, so a chart can mark them.
    /// </summary>
    /// <remarks>
    /// A run of one point produces a path that moves the pen and draws
    /// nothing, which renders as an empty chart - indistinguishable from
    /// having no data at all. A domain heard from once in a fortnight is
    /// exactly that case, and it is worth seeing. The caller draws these as
    /// dots.
    /// </remarks>
    public static IReadOnlyList<(double X, double Y)> IsolatedPoints(
        IReadOnlyList<double?> values, double width, double height, double? max = null)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0) { return []; }

        var top = Top(values, max);
        var points = new List<(double, double)>();

        for (var i = 0; i < values.Count; i++)
        {
            if (values[i] is not { } value) { continue; }

            var hasLeft = i > 0 && values[i - 1] is not null;
            var hasRight = i + 1 < values.Count && values[i + 1] is not null;
            if (hasLeft || hasRight) { continue; }

            points.Add((X(i, values.Count, width), Y(value, top, height)));
        }

        return points;
    }

    /// <summary>The horizontal centre of bucket <paramref name="index"/>.</summary>
    /// <remarks>
    /// A single bucket sits in the middle rather than at the left edge: one
    /// reading pinned to x=0 reads as the start of a trend that has not been
    /// measured.
    /// </remarks>
    public static double X(int index, int count, double width) =>
        count <= 1 ? width / 2 : width * index / (count - 1);

    /// <summary>Where a value sits vertically, with y growing downward as SVG does.</summary>
    public static double Y(double value, double max, double height) =>
        max <= 0 ? height : height - (Math.Clamp(value, 0, max) / max * height);

    /// <summary>
    /// A sensible top of scale.
    /// </summary>
    /// <remarks>
    /// Never zero, because dividing by it would put every point on the
    /// baseline or produce NaN, and an all-zero series is a real thing: a
    /// domain that sent nothing all week.
    /// </remarks>
    private static double Top(IReadOnlyList<double?> values, double? max)
    {
        if (max is { } given) { return given > 0 ? given : 1; }

        var highest = 0.0;
        foreach (var v in values)
        {
            if (v is { } value && value > highest) { highest = value; }
        }
        return highest > 0 ? highest : 1;
    }

    /// <summary>
    /// Formats a coordinate for the path.
    /// </summary>
    /// <remarks>
    /// Invariant culture, always. A machine set to a locale that writes
    /// decimals with a comma would emit "12,5 40" and produce a path the
    /// browser silently refuses to draw - a blank chart on one server and a
    /// correct one on another, with nothing in the logs.
    /// </remarks>
    private static string N(double value) =>
        Math.Round(value, 2).ToString("0.##", CultureInfo.InvariantCulture);
}
