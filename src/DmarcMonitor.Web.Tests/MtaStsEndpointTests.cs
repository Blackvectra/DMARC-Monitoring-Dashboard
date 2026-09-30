using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The half of MTA-STS this app serves rather than publishes.
///
/// The caller is another organization's mail server. It is anonymous, it is
/// not a browser, and RFC 8461 §3.3 says it must not follow a redirect when
/// fetching a policy - so every answer here has to be the real one. A 302 to a
/// sign-in page is not a worse 404; it is an answer a machine cannot read.
///
/// This exists because adding a friendly not-found PAGE broke it: re-executing
/// a 404 ran it back through the pipeline as a request for a page, that page
/// needed authentication, and a missing policy started answering senders with
/// a redirect to a login screen.
/// </summary>
public sealed class MtaStsEndpointTests : IClassFixture<PublicEndpointApp>
{
    private readonly PublicEndpointApp _app;

    public MtaStsEndpointTests(PublicEndpointApp app) => _app = app;

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
        // No cookie, no header, nothing. The caller is another organization's
        // mail server and has no way to authenticate to this instance.
        var response = await Client().SendAsync(Ask("mta-sts.nobody-configured-this.example"));

        Assert.DoesNotContain("local-signin", response.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
    }
}

/// <summary>
/// An instance that answers to names other than its own, which is what serving
/// MTA-STS means: <c>mta-sts.&lt;client domain&gt;</c> for every client, from the
/// Host header. Local trial mode answers only to localhost, so it cannot stand
/// in for this; a server with the local-mode guard switched off, and no sign-in
/// configured, can - and its default authentication is the one that redirects
/// to a login page, which is the failure these tests exist to keep out.
/// </summary>
public sealed class PublicEndpointApp : UnauthenticatedApp
{
    protected override string AllowLocalModeRemotely => "true";
}
