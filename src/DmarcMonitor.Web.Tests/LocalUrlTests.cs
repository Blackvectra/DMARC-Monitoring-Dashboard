using DmarcMonitor.Web.Auth;
using Xunit;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Where a redirect may send somebody.
///
/// Two endpoints take a return address, and an open redirect on either is a
/// phishing primitive: a link that genuinely starts with this instance's own
/// address and ends somewhere asking for a Microsoft password.
/// </summary>
public sealed class LocalUrlTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/domains")]
    [InlineData("/domains/acme.com")]
    [InlineData("/reports/download/acme-corp/2026-08")]
    [InlineData("/domains?find=acme&days=30")]
    [InlineData("/domains#sources")]
    public void APathInsideThisSiteIsKept(string url) =>
        Assert.Equal(url, LocalUrl.OrRoot(url));

    [Theory]
    // Protocol-relative: another host, and the one that was already refused.
    [InlineData("//evil.example")]
    [InlineData("//evil.example/steal")]
    // The bypass that was NOT refused. Several browsers normalize a backslash
    // here to a second slash, so this reaches the same place as the line above.
    [InlineData("/\\evil.example")]
    [InlineData("/\\/evil.example")]
    // Absolute, in any dress.
    [InlineData("https://evil.example")]
    [InlineData("http://evil.example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("evil.example")]
    // Nothing to go back to.
    [InlineData("")]
    [InlineData(null)]
    public void AnythingLeavingThisSiteBecomesTheFrontPage(string? url) =>
        Assert.Equal("/", LocalUrl.OrRoot(url));

    [Fact]
    public void AControlCharacterIsRefused()
    {
        // Response splitting. Kestrel will not send a header holding one, so
        // this is the second lock rather than the first.
        Assert.Equal("/", LocalUrl.OrRoot("/domains\r\nSet-Cookie: a=b"));
        Assert.Equal("/", LocalUrl.OrRoot("/domains\n"));
    }

    [Fact]
    public void ASingleSlashIsTheFrontPageAndIsAllowed() =>
        Assert.Equal("/", LocalUrl.OrRoot("/"));
}
