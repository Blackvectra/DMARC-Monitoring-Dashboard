namespace DmarcMonitor.Web.Data;

/// <summary>
/// How long ago, in the words a table can afford.
/// </summary>
/// <remarks>
/// Whole days, because every timestamp these pages show is a report's date
/// range or a scan's day, and "3 hours ago" would claim a precision the data
/// does not have.
/// </remarks>
public static class TimeAgo
{
    /// <summary>"today", "yesterday", "9 days ago", or "never" for a missing time.</summary>
    public static string Days(DateTimeOffset? when)
    {
        if (when is null) { return "never"; }

        var days = (int)(DateTimeOffset.UtcNow - when.Value).TotalDays;
        return days switch
        {
            <= 0 => "today",
            1 => "yesterday",
            _ => $"{days} days ago",
        };
    }
}
