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
        //
        // Asserted over every width on the page, not a single spelling of it.
        // This started as DoesNotContain("width:0,"), which is narrow enough
        // to pass on an en-US runner against a page that had the bug - and it
        // did. Chart.Percent is where the rule lives now, and ChartTests runs
        // it under a comma-decimal locale, which is the test that can really
        // catch it.
        var widths = System.Text.RegularExpressions.Regex.Matches(html, @"width:([^;""]+)")
            .Select(m => m.Groups[1].Value)
            .ToList();

        Assert.NotEmpty(widths);
        Assert.All(widths, w => Assert.DoesNotContain(",", w, StringComparison.Ordinal));
        Assert.All(widths, w => Assert.Matches(@"^\d+(\.\d+)?%$", w));
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
        // as not knowing, never as an absent record. Checked per chip on the
        // failed domain rather than by looking for "chip missing" anywhere on
        // the page - acme.com really does publish no MTA-STS and no TLS-RPT,
        // so a cross for those is now correct, and an assertion about the
        // whole page would have to be weakened to stay true.
        Assert.Contains("chip unreadable", html, StringComparison.Ordinal);

        foreach (var record in new[] { "SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT" })
        {
            Assert.Contains(
                $"aria-label=\"{record} for signed.example: The last attempt to read the DNS",
                html, StringComparison.Ordinal);
        }

        // And the domain that really publishes neither transport record says
        // so, which is the reason those two chips exist.
        Assert.Contains(
            "aria-label=\"MTA-STS for acme.com: No TXT record at _mta-sts.acme.com",
            html, StringComparison.Ordinal);
        Assert.Contains(
            "aria-label=\"TLS-RPT for acme.com: No TXT record at _smtp._tls.acme.com",
            html, StringComparison.Ordinal);

        // And the banner now dates the readings rather than saying there are
        // none.
        Assert.Contains("DNS last read", html, StringComparison.Ordinal);
    }
}
