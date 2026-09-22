using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// That the fetcher looks a name up again rather than trusting the answer it
/// got when the process started.
///
/// From a real report: a domain whose policy host had been published hours
/// earlier was still shown as "there is no host at mta-sts.&lt;domain&gt;", while
/// a browser tab open beside it was serving the policy from that exact URL.
///
/// The cause was not the check. MtaStsFetcher is registered as a singleton,
/// its HttpClient lives as long as the process, and
/// SocketsHttpHandler.PooledConnectionLifetime defaults to infinite - so the
/// name behind a pooled connection is resolved once and never again. That is
/// the documented long-lived HttpClient behaviour, and it is ordinarily a
/// minor staleness. Here it is not minor: this application's entire subject
/// is what DNS says right now, so an instance holding a stale answer is not
/// degraded, it is confidently wrong about the only thing it was asked.
/// </summary>
public sealed class MtaStsFetcherDnsRefreshTests
{
    [Fact]
    public void TheConnectionPoolExpiresSoDnsIsLookedUpAgain()
    {
        using var handler = MtaStsFetcher.DefaultHandler();

        Assert.NotEqual(Timeout.InfiniteTimeSpan, handler.PooledConnectionLifetime);
        Assert.Equal(MtaStsFetcher.DnsRefresh, handler.PooledConnectionLifetime);
    }

    /// <summary>
    /// Bounded at both ends on purpose. Too long and a policy host that moved
    /// is reported against the old address for the rest of the day; too short
    /// and every check pays for a new connection to a host that has not
    /// changed in months.
    /// </summary>
    [Fact]
    public void TheRefreshIntervalIsMinutesRatherThanHoursOrSeconds()
    {
        Assert.InRange(MtaStsFetcher.DnsRefresh, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(15));
    }

    /// <summary>
    /// The other half of the original bug, and the part that is not about
    /// caching at all: a sender fetching a policy must not follow a redirect,
    /// so neither may this. A policy reached by redirect is one any domain
    /// could claim for another.
    /// </summary>
    [Fact]
    public void RedirectsAreStillNotFollowed()
    {
        using var handler = MtaStsFetcher.DefaultHandler();

        Assert.False(handler.AllowAutoRedirect);
    }
}
