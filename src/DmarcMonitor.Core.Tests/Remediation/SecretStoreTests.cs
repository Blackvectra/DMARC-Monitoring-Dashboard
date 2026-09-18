using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// Where a provider token lives, and where it must not.
/// </summary>
public sealed class SecretStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-secrets-{Guid.NewGuid():N}");
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-prov-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task RoundTripsASecretWithoutWritingItInClear()
    {
        var store = new LocalSecretStore(_dir);
        var reference = CredentialRef.New("local", "cloudflare");

        await store.SetAsync(reference, "cf-token-abc123");

        Assert.Equal("cf-token-abc123", await store.GetAsync(reference));
        var onDisk = File.ReadAllText(Path.Combine(_dir, "secrets.json"));
        Assert.DoesNotContain("cf-token-abc123", onDisk, StringComparison.Ordinal);
        Assert.Contains(reference, onDisk, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NothingStoredIsNullNotAnError()
    {
        var store = new LocalSecretStore(_dir);

        Assert.Null(await store.GetAsync(CredentialRef.New("local", "cloudflare")));
    }

    [Fact]
    public async Task RemovedIsGone()
    {
        var store = new LocalSecretStore(_dir);
        var reference = CredentialRef.New("local", "azuredns");
        await store.SetAsync(reference, "s");

        await store.RemoveAsync(reference);

        Assert.Null(await store.GetAsync(reference));
    }

    [Theory]
    [InlineData("dmarc.local.cloudflare.0123456789abcdef", true)]
    [InlineData("dmarc.local.cloudflare.0123", false)]
    [InlineData("../../etc/passwd", false)]
    [InlineData("dmarc.local.cloud flare.0123456789abcdef", false)]
    [InlineData("", false)]
    public void OnlyARefThisToolMintedIsAccepted(string value, bool valid)
    {
        // A ref becomes a key in the backend's own namespace. One that can
        // name anything else there is a path traversal waiting to happen.
        Assert.Equal(valid, CredentialRef.IsValid(value));
    }

    [Fact]
    public void MintedRefsAreNamespacedAndUnique()
    {
        var a = CredentialRef.New("NRG Tech", "cloudflare");
        var b = CredentialRef.New("NRG Tech", "cloudflare");

        Assert.StartsWith("dmarc.nrgtech.cloudflare.", a, StringComparison.Ordinal);
        Assert.NotEqual(a, b);
        Assert.True(CredentialRef.IsValid(a));
    }

    [Fact]
    public async Task TheDatabaseRowHoldsTheRefAndNeverTheToken()
    {
        var store = new ReportStore(_dbPath);
        await store.InitialiseAsync(DatabaseSchema.Sql);
        var xml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dmv-google-aggregate.xml"));
        await store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, null);
        await store.CreateClientAsync("DMV");
        await store.AssignDomainAsync("dmvwrr.com", "dmv");

        var secrets = new InMemorySecretStore();
        var configs = new DnsProviderConfigs(_dbPath, secrets);

        var config = await configs.SetAsync("dmv", null, "cloudflare",
            new Dictionary<string, string> { ["zone_id"] = "zone1" }, "cf-token-abc123");

        Assert.NotNull(config.CredentialRef);
        Assert.Equal("cf-token-abc123", await secrets.GetAsync(config.CredentialRef));

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT config_json || credential_ref FROM dns_provider_configs";
        var row = (string)(await command.ExecuteScalarAsync())!;
        Assert.DoesNotContain("cf-token", row, StringComparison.Ordinal);

        // The config applies to every domain of the client, and builds a
        // provider that has the token.
        var provider = await configs.ProviderForAsync("dmvwrr.com");
        Assert.Equal("cloudflare", provider.Name);
        Assert.True(provider.CanWrite);
    }

    [Fact]
    public async Task ADomainConfigWinsOverItsClients()
    {
        var store = new ReportStore(_dbPath);
        await store.InitialiseAsync(DatabaseSchema.Sql);
        var xml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dmv-google-aggregate.xml"));
        await store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, null);
        await store.CreateClientAsync("DMV");
        await store.AssignDomainAsync("dmvwrr.com", "dmv");
        var configs = new DnsProviderConfigs(_dbPath, new InMemorySecretStore());

        await configs.SetAsync("dmv", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "z" }, "t");
        await configs.SetAsync("dmv", "dmvwrr.com", "manual", new Dictionary<string, string>(), null);

        var applies = await configs.ForDomainAsync("dmvwrr.com");
        Assert.Equal("manual", applies!.Provider);
        Assert.Equal(2, (await configs.ListAsync()).Count);
    }

    [Fact]
    public async Task ReplacingAConfigRemovesTheOldSecret()
    {
        var store = new ReportStore(_dbPath);
        await store.InitialiseAsync(DatabaseSchema.Sql);
        var xml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dmv-google-aggregate.xml"));
        await store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, null);
        await store.CreateClientAsync("DMV");
        var secrets = new InMemorySecretStore();
        var configs = new DnsProviderConfigs(_dbPath, secrets);

        var first = await configs.SetAsync("dmv", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "z" }, "old");
        await configs.SetAsync("dmv", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "z" }, "new");

        Assert.Null(await secrets.GetAsync(first.CredentialRef!));
        Assert.Single(await configs.ListAsync());
    }

    [Fact]
    public async Task CloudflareWithoutATokenIsRefusedWithTheReason()
    {
        var store = new ReportStore(_dbPath);
        await store.InitialiseAsync(DatabaseSchema.Sql);
        await store.CreateClientAsync("DMV");
        var configs = new DnsProviderConfigs(_dbPath, new InMemorySecretStore());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            configs.SetAsync("dmv", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "z" }, null));

        Assert.Contains("never the Global API Key", ex.Message, StringComparison.Ordinal);
    }
}
