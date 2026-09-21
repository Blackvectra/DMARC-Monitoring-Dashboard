using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The headers a browser needs to defend these pages.
///
/// Worth pinning rather than trusting, because a content security policy that
/// is wrong in either direction fails silently: too loose and it defends
/// nothing, too strict and the page renders blank with the reason only in a
/// console nobody has open.
/// </summary>
public sealed class SecurityHeaderTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public SecurityHeaderTests(SeededApp app) => _app = app;

    // Local trial mode redirects to its own sign-in and sets a cookie, so the
    // headers worth checking are on the page that comes after it.
    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    [Theory]
    [InlineData("/")]
    [InlineData("/domains")]
    [InlineData("/settings")]
    [InlineData("/app.css")]
    public async Task EveryResponseCarriesThem(string route)
    {
        var response = await Client().GetAsync(route);

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePolicyAllowsWhatTheAppActuallyDoes()
    {
        // A policy that forbids what the shell needs is worse than none: the
        // menu and the theme toggle stop working, and the page still renders,
        // so nothing looks broken until somebody clicks.
        var csp = (await Client().GetAsync("/")).Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("script-src 'self' 'unsafe-inline'", csp, StringComparison.Ordinal);  // the shell's onclick handlers
        Assert.Contains("style-src 'self' 'unsafe-inline'", csp, StringComparison.Ordinal);   // charts, and the brand accent
        Assert.Contains("img-src 'self' data:", csp, StringComparison.Ordinal);               // an organization's logo
        Assert.Contains("connect-src 'self'", csp, StringComparison.Ordinal);                 // Blazor's circuit
    }

    [Fact]
    public async Task ThePolicyStillForbidsWhatMatters()
    {
        var csp = (await Client().GetAsync("/")).Headers.GetValues("Content-Security-Policy").Single();

        // 'unsafe-inline' is a concession to three onclick attributes. It must
        // not become a concession to loading script off somebody's CDN, which
        // is the injection that matters on a server we do not own.
        Assert.DoesNotContain("script-src 'self' 'unsafe-inline' http", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("*", csp, StringComparison.Ordinal);
        Assert.Contains("object-src 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("base-uri 'self'", csp, StringComparison.Ordinal);
        Assert.Contains("form-action 'self'", csp, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AClientReportIsHeldToAStricterPolicyThanTheApp()
    {
        // The report is built from data strangers supplied - anybody can send
        // a report to a customer's rua address - and it needs no script at
        // all, which is already a test of its own. So it gets the policy the
        // app cannot have.
        var response = await Client().GetAsync("/reports/download/acme-corp/2026-08");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var csp = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("script-src 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", csp, StringComparison.Ordinal);

        // No 'self' anywhere: the report is a document, not part of the app,
        // and it must not be able to pull anything back off this origin
        // either. That is what makes it safe to mail and to open from a
        // folder, which is where it ends up.
        Assert.DoesNotContain("'self'", csp, StringComparison.Ordinal);
    }
}
