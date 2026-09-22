using DmarcMonitor.Web.Auth;
using Microsoft.Extensions.Configuration;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Which of the three shapes this application runs in should redirect HTTP to
/// HTTPS itself.
///
/// It used to be two questions and needed three. The trial copy - loopback
/// only, plain HTTP, no certificate - was told to redirect, could not work out
/// a port to redirect to, and said so on every single start:
///
///     warn: Microsoft.AspNetCore.HttpsPolicy.HttpsRedirectionMiddleware[3]
///           Failed to determine the https port for redirect.
///
/// It redirected nothing, so nothing was broken. But it was the last line
/// printed before somebody decided whether the thing they had just downloaded
/// worked, and a warning there costs more than it looks.
/// </summary>
public sealed class HttpsRedirectTests
{
    private static IConfiguration Config(params (string Key, string Value)[] settings) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value)))
            .Build();

    /// <summary>
    /// The case this was written for.
    /// </summary>
    [Fact]
    public void TheTrialCopyDoesNotRedirect()
    {
        // Nothing configured at all: what the Windows download runs as.
        Assert.False(ProxySetup.ShouldRedirectToHttps(Config()));
    }

    [Fact]
    public void AnInstanceWithSignInAndNoProxyStillRedirects()
    {
        // The case the original rule was written for, and it must not change:
        // a deployment holding its own certificate has to get people off
        // plain HTTP itself, because nothing in front of it will.
        var configuration = Config(
            ("AzureAd:TenantId", "11111111-1111-1111-1111-111111111111"),
            ("AzureAd:ClientId", "22222222-2222-2222-2222-222222222222"));

        Assert.True(ProxySetup.ShouldRedirectToHttps(configuration));
    }

    [Fact]
    public void LocalModeDeliberatelyExposedStillRedirects()
    {
        // No sign-in, but somebody has explicitly allowed it beyond loopback.
        // That is a decision rather than a trial, and it is the shape most in
        // need of not being served over plain HTTP.
        Assert.True(ProxySetup.ShouldRedirectToHttps(Config(("Auth:AllowLocalModeRemotely", "true"))));
    }

    [Fact]
    public void BehindAProxyNothingRedirectsTwice()
    {
        // The proxy already did it. Doing it again on a request forwarded as
        // HTTP is the redirect loop that reads as the app being down.
        var configuration = Config(
            ("Proxy:Behind", "true"),
            ("AzureAd:TenantId", "11111111-1111-1111-1111-111111111111"),
            ("AzureAd:ClientId", "22222222-2222-2222-2222-222222222222"));

        Assert.False(ProxySetup.ShouldRedirectToHttps(configuration));
    }
}
