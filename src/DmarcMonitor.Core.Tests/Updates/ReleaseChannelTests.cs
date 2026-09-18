using System.Net;
using System.Text;
using DmarcMonitor.Core.Updates;

namespace DmarcMonitor.Core.Tests.Updates;

/// <summary>
/// Knowing whether a deployed instance is behind a release.
///
/// The asymmetry these are built around: failing to mention an update costs a
/// line on a page, and wrongly announcing one sends somebody to replace a
/// working install on a machine managing customers' DNS. So anything it
/// cannot establish, it does not claim.
/// </summary>
public sealed class ReleaseChannelTests
{
    private sealed class Answer(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? Seen { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Seen = request;
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static string Releases(params string[] entries) => "[" + string.Join(",", entries) + "]";

    private static string Entry(string tag, bool prerelease = false, bool draft = false, string published = "2026-09-01T00:00:00Z") =>
        $$"""
        {"tag_name":"{{tag}}","name":"{{tag}}","html_url":"https://example/{{tag}}",
         "draft":{{(draft ? "true" : "false")}},"prerelease":{{(prerelease ? "true" : "false")}},
         "published_at":"{{published}}"}
        """;

    // ---- the comparison ------------------------------------------------------

    [Theory]
    [InlineData("1.3.0", "1.2.0", true)]
    [InlineData("1.2.1", "1.2.0", true)]
    [InlineData("2.0", "1.9.9", true)]
    [InlineData("1.2.0", "1.2.0", false)]
    [InlineData("1.2.0", "1.3.0", false)]
    [InlineData("v1.3.0", "1.2.0", true)]
    [InlineData("1.3.0-rc1", "1.2.0", true)]
    public void ComparesVersionsTheWayPeopleExpect(string candidate, string running, bool newer)
    {
        Assert.Equal(newer, ReleaseChannel.IsNewer(candidate, running));
    }

    [Theory]
    [InlineData("banana", "1.2.0")]
    [InlineData("1.3.0", "banana")]
    [InlineData("", "1.2.0")]
    [InlineData("development", "1.2.0")]
    public void SaysNothingAboutVersionsItCannotRead(string candidate, string running)
    {
        // Refusing to answer is the safe direction. Guessing "newer" sends
        // somebody to replace a working install.
        Assert.False(ReleaseChannel.IsNewer(candidate, running));
    }

    // ---- what it reports -----------------------------------------------------

    [Fact]
    public async Task NoticesANewerRelease()
    {
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, Releases(Entry("v1.3.0")))));

        var status = await channel.CheckAsync("owner/repo", "1.2.0");

        Assert.True(status.UpdateAvailable);
        Assert.Equal("1.3.0", status.Latest?.Version);
        Assert.Contains("1.3.0 is available", status.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaysSoWhenItIsAlreadyCurrent()
    {
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, Releases(Entry("v1.2.0")))));

        var status = await channel.CheckAsync("owner/repo", "1.2.0");

        Assert.False(status.UpdateAvailable);
        Assert.Contains("newest release", status.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheStableChannelIgnoresPrereleases()
    {
        // The whole point of a channel: a box running customers' DNS should
        // not be told to install a release candidate.
        var body = Releases(
            Entry("v1.4.0-rc1", prerelease: true, published: "2026-09-10T00:00:00Z"),
            Entry("v1.3.0", published: "2026-09-01T00:00:00Z"));

        var status = await new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, body)))
            .CheckAsync("owner/repo", "1.2.0");

        Assert.Equal("1.3.0", status.Latest?.Version);
    }

    [Fact]
    public async Task ThePreviewChannelTakesThem()
    {
        var body = Releases(
            Entry("v1.4.0-rc1", prerelease: true, published: "2026-09-10T00:00:00Z"),
            Entry("v1.3.0", published: "2026-09-01T00:00:00Z"));

        var status = await new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, body)))
            .CheckAsync("owner/repo", "1.2.0", ReleaseChannel.Preview);

        Assert.Equal("1.4.0-rc1", status.Latest?.Version);
    }

    [Fact]
    public async Task DraftsAreNotReleases()
    {
        var body = Releases(
            Entry("v9.9.9", draft: true, published: "2026-09-10T00:00:00Z"),
            Entry("v1.3.0", published: "2026-09-01T00:00:00Z"));

        var status = await new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, body)))
            .CheckAsync("owner/repo", "1.2.0");

        Assert.Equal("1.3.0", status.Latest?.Version);
    }

    [Fact]
    public async Task ADevelopmentBuildIsNotToldToUpdate()
    {
        // Somebody running their own build has not fallen behind; telling
        // them to update means telling them to overwrite their work.
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, Releases(Entry("v9.9.9")))));

        var status = await channel.CheckAsync("owner/repo", BuildInfo.DevelopmentVersion);

        Assert.False(status.UpdateAvailable);
        Assert.Contains("development build", status.Summary, StringComparison.Ordinal);
    }

    // ---- when it cannot tell -------------------------------------------------

    [Fact]
    public async Task APrivateRepositoryWithNoTokenSaysWhatIsMissing()
    {
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.NotFound, "{}")));

        var status = await channel.CheckAsync("owner/repo", "1.2.0");

        Assert.False(status.UpdateAvailable);
        Assert.Contains("access token", status.Problem!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BeingRateLimitedIsNotAnUpdate()
    {
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.Forbidden, "{}")));

        var status = await channel.CheckAsync("owner/repo", "1.2.0");

        Assert.False(status.UpdateAvailable);
        Assert.Contains("rate-limiting", status.Problem!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoReleasesAtAllIsNotAFailure()
    {
        var channel = new ReleaseChannel(new HttpClient(new Answer(HttpStatusCode.OK, "[]")));

        var status = await channel.CheckAsync("owner/repo", "1.2.0");

        Assert.False(status.UpdateAvailable);
        Assert.Null(status.Problem);
        Assert.Contains("Nothing has been released", status.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendsTheHeadersGitHubInsistsOn()
    {
        // GitHub rejects a request with no User-Agent outright, which would
        // look exactly like "no updates" forever.
        var answer = new Answer(HttpStatusCode.OK, "[]");

        await new ReleaseChannel(new HttpClient(answer)).CheckAsync("owner/repo", "1.2.0", token: "secret");

        Assert.NotEmpty(answer.Seen!.Headers.UserAgent);
        Assert.Equal("Bearer", answer.Seen.Headers.Authorization?.Scheme);
    }
}
