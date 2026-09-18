using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Where the cookie-signing keys live.
///
/// Left to itself, ASP.NET Core keeps them under the service account's home
/// directory. A systemd unit that hides the home directory - ProtectHome=true,
/// the right setting for a service - then gets keys that exist only in
/// memory, and everybody is signed out every time the service restarts. That
/// presents as a flaky login and is diagnosed as anything but a file path.
///
/// So they live beside the database, where the backup already goes, and the
/// unit file can hide the home directory.
/// </summary>
public sealed class DataProtectionTests
{
    [Fact]
    public async Task KeysArePersistedBesideTheDatabase()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"dmarc-keys-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var dbPath = Path.Combine(dir, "dmarc.db");
            await new ReportStore(dbPath).InitialiseAsync(DatabaseSchema.Sql);

            using var app = new KeyedApp(dbPath);
            var client = app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            // Signing in issues a cookie, and a cookie needs a key: this is the
            // first moment a key has to exist on disk.
            var response = await client.GetAsync("/local-signin");
            Assert.True(response.Headers.Contains("Set-Cookie"), "local sign-in did not issue a cookie");

            var keys = Directory.Exists(Path.Combine(dir, "keys"))
                ? Directory.GetFiles(Path.Combine(dir, "keys"), "key-*.xml")
                : [];

            Assert.NotEmpty(keys);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    private sealed class KeyedApp(string dbPath) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("Database:Path", dbPath);
            builder.UseSetting("AzureAd:TenantId", "");
            builder.UseSetting("AzureAd:ClientId", "");
        }
    }
}
