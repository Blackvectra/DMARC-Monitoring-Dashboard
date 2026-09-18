using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The half of MTA-STS this app serves rather than publishes.
///
/// The caller is another organisation's mail server. It is anonymous, it is
/// not a browser, and RFC 8461 §3.3 says it must not follow a redirect when
/// fetching a policy - so every answer here has to be the real one. A 302 to a
/// sign-in page is not a worse 404; it is an answer a machine cannot read.
///
/// This exists because adding a friendly not-found PAGE broke it: re-executing
/// a 404 ran it back through the pipeline as a request for a page, that page
/// needed authentication, and a missing policy started answering senders with
/// a redirect to a login screen.
/// </summary>
public sealed class MtaStsEndpointTests : IClassFixture<UnauthenticatedApp>
{
    private readonly UnauthenticatedApp _app;

    public MtaStsEndpointTests(UnauthenticatedApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    private static HttpRequestMessage Ask(string host)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/mta-sts.txt");
        request.Headers.Host = host;
        return request;
    }

    [Fact]
    public async Task ADomainWithNoPolicyGetsAPlainNotFound()
    {
        var response = await Client().SendAsync(Ask("mta-sts.nobody-configured-this.example"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AHostThatIsNotAnMtaStsNameGetsAPlainNotFound()
    {
        // Answering this would let the instance be used to claim a policy for
        // a name nobody asked about.
        var response = await Client().SendAsync(Ask("evil.example"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("mta-sts.nobody-configured-this.example")]
    [InlineData("evil.example")]
    public async Task ItNeverAnswersASenderWithARedirect(string host)
    {
        // The regression itself, stated as the rule rather than as a status
        // code: whatever this endpoint answers, it is never "go and sign in".
        var response = await Client().SendAsync(Ask(host));

        Assert.NotEqual(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Found, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task ASenderDoesNotHaveToSignIn()
    {
        // No cookie, no header, nothing. The caller is another organisation's
        // mail server and has no way to authenticate to this instance.
        var response = await Client().SendAsync(Ask("mta-sts.nobody-configured-this.example"));

        Assert.DoesNotContain("local-signin", response.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
    }
}
