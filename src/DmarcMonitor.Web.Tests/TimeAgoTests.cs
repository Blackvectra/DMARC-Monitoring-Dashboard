using DmarcMonitor.Web.Data;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// "How long ago", in whole days: the words the tables use for a report's date
/// and a scan's day, where "3 hours ago" would claim a precision the data does
/// not have.
/// </summary>
public sealed class TimeAgoTests
{
    [Theory]
    [InlineData(0, "today")]
    [InlineData(0.5, "today")]
    [InlineData(1, "yesterday")]
    [InlineData(1.9, "yesterday")]
    [InlineData(2, "2 days ago")]
    [InlineData(9, "9 days ago")]
    [InlineData(400, "400 days ago")]
    public void SaysWholeDays(double daysAgo, string expected) =>
        Assert.Equal(expected, TimeAgo.Days(DateTimeOffset.UtcNow.AddDays(-daysAgo).AddMinutes(-1)));

    [Fact]
    public void ATimeInTheFutureIsToday()
    {
        // A clock a little ahead of the report's must not print "-1 days ago".
        Assert.Equal("today", TimeAgo.Days(DateTimeOffset.UtcNow.AddHours(5)));
    }

    [Fact]
    public void NoTimeAtAllIsNever() => Assert.Equal("never", TimeAgo.Days(null));
}
