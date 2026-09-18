using System.Net;
using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Local trial mode behind a reverse proxy.
///
/// The guard refuses anything that is not loopback, and every deployment shape
/// there is puts a proxy in front to hold the TLS certificate. Behind one,
/// every request arrives from 127.0.0.1 - so the check that is supposed to
/// keep an unauthenticated instance private passes for the entire internet.
///
/// These are about that one sentence. An instance with no sign-in must not
/// serve a request that came through a proxy, whatever address it appears to
/// come from and whether or not anybody configured the forwarded headers.
/// </summary>
public sealed class ProxyTests : IClassFixture<UnauthenticatedApp>
{
    private readonly UnauthenticatedApp _app;

    public ProxyTests(UnauthenticatedApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Theory]
    [InlineData("X-Forwarded-For", "203.0.113.9")]
    [InlineData("X-Forwarded-Proto", "https")]
    [InlineData("X-Forwarded-Host", "dmarc.example.com")]
    [InlineData("Forwarded", "for=203.0.113.9;proto=https")]
    // nginx's other convention, and Apache's. A proxy set up with only one of
    // these and none of the X-Forwarded-* family is unusual but writable in a
    // few lines, and it used to walk straight past the guard.
    [InlineData("X-Real-IP", "203.0.113.9")]
    [InlineData("X-Forwarded-Server", "dmarc.example.com")]
    public async Task RefusesARequestThatCameThroughAProxy(string header, string value)
    {
        // The test host connects over loopback, exactly as a proxy on the same
        // machine would, so the address check alone would let this straight
        // through.
        var client = Client();
        client.DefaultRequestHeaders.Add(header, value);

        var response = await client.GetAsync("/");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("reverse proxy", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaysWhatToDoAboutIt()
    {
        // Somebody who hits this is mid-deployment. The refusal has to name
        // both ways out, or it reads as the app being broken.
        var client = Client();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.9");

        var body = await (await client.GetAsync("/")).Content.ReadAsStringAsync();

        Assert.Contains("AzureAd", body, StringComparison.Ordinal);
        Assert.Contains("Auth:AllowLocalModeRemotely", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnOrdinaryLocalRequestIsStillServed()
    {
        // The guard must not have become "refuse everything". Local mode with
        // nobody in front of it is how this gets trialled.
        var response = await Client().GetAsync("/");

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }
}

/// <summary>The app with no Entra configured, which is what local trial mode means.</summary>
public sealed class UnauthenticatedApp : WebApplicationFactory<Program>
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-proxy-{Guid.NewGuid():N}.db");

    public UnauthenticatedApp() =>
        new ReportStore(_dbPath).InitialiseAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Database:Path", _dbPath);

        // Explicitly not configured, which is the state these are about.
        builder.UseSetting("AzureAd:TenantId", "");
        builder.UseSetting("AzureAd:ClientId", "");
        builder.UseSetting("Auth:AllowLocalModeRemotely", "false");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) { return; }

        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }
}
