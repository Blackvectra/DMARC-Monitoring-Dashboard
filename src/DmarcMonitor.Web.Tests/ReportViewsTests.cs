using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The aggregate reports page: one window read five ways.
///
/// Every summary elsewhere in the product is one of these views with the rows
/// folded up, and the moment somebody disbelieves a summary - which is the
/// moment that matters - this is where they go. So what these assert is that
/// each view exists, is reachable by its own address, and says which bucket a
/// row is in rather than only whether it passed.
/// </summary>
public sealed class ReportViewsTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public ReportViewsTests(SeededApp app) => _app = app;

    private Task<string> PageAsync(string url = "/reports/views") => _app
        .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
        .GetStringAsync(url);

    [Fact]
    public async Task EveryViewIsOfferedByName()
    {
        var html = await PageAsync();

        foreach (var tab in new[]
                 { "Per sending source", "Per result", "Per organization", "Per host", "Detailed stats" })
        {
            Assert.Contains(tab, html, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A view is an address, so an analyst can send somebody the one they
    /// mean rather than a page plus instructions for finding it.
    /// </summary>
    [Fact]
    public async Task AViewCanBeLinkedTo()
    {
        var html = await PageAsync("/reports/views?view=Per%20result");

        Assert.Contains("aria-selected=\"true\"", html, StringComparison.Ordinal);

        // The middle bucket is the reason this view exists: a service that
        // authenticates and does not align is a configuration job, and any
        // view with only pass and fail files it beside the forgers.
        Assert.Contains("Authenticated, not aligned", html, StringComparison.Ordinal);
        Assert.Contains("DMARC correct", html, StringComparison.Ordinal);

        // Asserted around the dash rather than through it: Blazor's HTML
        // encoder escapes everything outside Basic Latin, so an em dash
        // reaches the page as &#x2014; and a test looking for the character
        // fails against markup that is perfectly correct.
        Assert.Contains("neither check passed", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnknownViewFallsBackRatherThanRenderingNothing()
    {
        // A hand-typed view=whatever would otherwise select no tab at all and
        // draw an empty page under a row of headings.
        var html = await PageAsync("/reports/views?view=nonsense");

        Assert.Contains("aria-selected=\"true\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The name and the address are two lines, not one string.
    /// </summary>
    /// <remarks>
    /// Both classes were defined only inside the client report's own
    /// stylesheet, so in the application the spans ran together and a row read
    /// "a3i117.smtp2go.com203.31.36.117".
    /// </remarks>
    [Fact]
    public async Task ANamedSourceIsStyledAsTwoLines()
    {
        var css = await _app
            .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, HandleCookies = true })
            .GetStringAsync("/app.css");

        Assert.Contains(".src-name { display: block;", css, StringComparison.Ordinal);
        Assert.Contains(".src-ip {", css, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheReportingGroupOffersItBeforeTheDocument()
    {
        // The raw reports first, then what gets sent to a customer: an analyst
        // opens this group to answer a question, and the document is what is
        // produced afterwards.
        var html = await PageAsync();

        var views = html.IndexOf("reports/views", StringComparison.Ordinal);
        var client = html.IndexOf(">Client reports<", StringComparison.Ordinal);

        Assert.True(views >= 0, "the nav does not link the aggregate reports page");
        Assert.True(client > views, "client reports should follow the aggregate views in the nav");
    }
}
