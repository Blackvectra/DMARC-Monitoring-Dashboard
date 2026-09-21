using DmarcMonitor.Core.Dns;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The domains table on an install where nothing has read DNS yet.
///
/// Its own fixture, and it writes nothing. A test that stores a reading would
/// otherwise decide what this one sees, depending on the order the runner
/// happened to pick - and the state being pinned here is precisely the
/// absence of readings.
/// </summary>
public sealed class DomainsTableUnreadTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public DomainsTableUnreadTests(SeededApp app) => _app = app;

    private Task<string> PageAsync() => _app
        .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
        .GetStringAsync("/domains");

    [Fact]
    public async Task NothingScannedYetSaysSoRatherThanDrawingCrosses()
    {
        // Reports but no DNS readings is exactly a fresh install on its first
        // afternoon. Three crosses per row there would read as every customer
        // having no records at all, and somebody would act on it.
        var html = await PageAsync();

        Assert.Contains("DNS has not been read yet", html, StringComparison.Ordinal);
        Assert.Contains("chip unknown", html, StringComparison.Ordinal);
        Assert.DoesNotContain("chip missing", html, StringComparison.Ordinal);
        Assert.DoesNotContain("chip ok", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheUnreadStateNamesTheCommandThatFillsIt()
    {
        // A dash with no explanation is a feature that looks broken.
        Assert.Contains("dmarc check --all --save", await PageAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryRowCarriesAVolumeBar()
    {
        var html = await PageAsync();

        Assert.Contains("vol-bar", html, StringComparison.Ordinal);

        // Written invariantly. A machine whose locale uses a comma for the
        // decimal point would emit width:33,3%, which browsers drop as an
        // invalid declaration - leaving every bar at its default width. The
        // page still renders, so it would look like a styling quirk rather
        // than a bug.
        Assert.DoesNotContain("width:0,", html, StringComparison.Ordinal);
        Assert.Matches(@"width:\d+(\.\d+)?%", html);
    }

    [Fact]
    public async Task TheBusiestDomainOnScreenFillsItsBar()
    {
        // Relative to what is shown, so the column can be ranked by eye. With
        // nothing reaching 100% the scale would be arbitrary.
        Assert.Contains("width:100%", await PageAsync(), StringComparison.Ordinal);
    }
}

/// <summary>
/// The same table once readings exist.
///
/// One test, seeding both domains at once. Split into several, each would be
/// writing into the fixture the others read, and the suite would pass or fail
/// on the order the runner chose.
/// </summary>
public sealed class DomainsTableReadingsTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public DomainsTableReadingsTests(SeededApp app) => _app = app;

    [Fact]
    public async Task StoredReadingsReachTheTable()
    {
        var store = new DnsSnapshotStore(_app.DatabasePath);

        await store.SaveAsync("acme.com", new PublishedRecords
        {
            Domain = "acme.com",
            SpfRecords = ["v=spf1 include:_spf.example.net -all"],
            DmarcRecord = "v=DMARC1; p=reject; rua=mailto:dmarc@example.net",
            SpfLookups = 3,
        });

        // A different domain whose lookup failed, so both outcomes are on the
        // page at once and neither can be borrowing the other's answer.
        await store.SaveAsync("signed.example",
            new PublishedRecords { Domain = "signed.example", LookupFailed = true });

        var html = await _app
            .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
            .GetStringAsync("/domains");

        Assert.Contains("chip ok", html, StringComparison.Ordinal);
        Assert.Contains("p=reject, reports to mailto:dmarc@example.net.", html, StringComparison.Ordinal);

        // The rule this whole column rests on: a lookup that failed is drawn
        // as not knowing, never as an absent record.
        Assert.Contains("chip unreadable", html, StringComparison.Ordinal);
        Assert.Contains("not the same as having no", html, StringComparison.Ordinal);
        Assert.DoesNotContain("chip missing", html, StringComparison.Ordinal);

        // And the banner now dates the readings rather than saying there are
        // none.
        Assert.Contains("DNS last read", html, StringComparison.Ordinal);
    }
}
