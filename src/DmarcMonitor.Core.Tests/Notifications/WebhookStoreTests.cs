using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Notifications;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Xunit;

namespace DmarcMonitor.Core.Tests.Notifications;

/// <summary>
/// Where an organization's findings go, and the rule that the database never
/// holds a secret - which here includes the address, because for most chat
/// tools the address is the credential.
/// </summary>
public sealed class WebhookStoreTests : IDisposable
{
    private const string Secret = "store-test-secret-0123456789abcdef0123";
    private const string SlackStyle = "https://hooks.chat.example/services/T0001/B0002/XyZtOkEnThatPostsAsYou";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-webhooks-{Guid.NewGuid():N}.db");
    private readonly InMemorySecretStore _secrets = new();
    private readonly WebhookStore _store;

    public WebhookStoreTests()
    {
        var reports = new ReportStore(_dbPath);
        reports.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        var xml = SyntheticReports.AggregateXml("store-1", "client.example");
        reports.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, "msg-1").GetAwaiter().GetResult();

        _store = new WebhookStore(_dbPath, _secrets);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    [Fact]
    public async Task TheAddressAndKeyAreKeptOutOfTheDatabase()
    {
        var hook = await _store.SetAsync("local", SlackStyle, Secret, "warning", null, "tester");

        Assert.Equal("https://hooks.chat.example", hook.Destination);

        // Read the file as bytes rather than through a query: whatever a
        // copied database or a backup would carry, this is it.
        var onDisk = await File.ReadAllTextAsync(_dbPath);
        Assert.DoesNotContain("XyZtOkEnThatPostsAsYou", onDisk, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, onDisk, StringComparison.Ordinal);

        var kept = await _secrets.GetAsync(hook.CredentialRef);
        Assert.Contains("XyZtOkEnThatPostsAsYou", kept, StringComparison.Ordinal);
        Assert.Contains(Secret, kept, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://receiver.example/hook")]
    [InlineData("ftp://receiver.example/hook")]
    [InlineData("not an address")]
    public async Task AnythingButHttpsElsewhereIsRefused(string url)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _store.SetAsync("local", url, Secret, "warning", null, "tester"));
    }

    /// <summary>A receiver on this machine, or one being tried out, is the one case plain HTTP is fine.</summary>
    [Theory]
    [InlineData("http://127.0.0.1:5080/hooks/dmarc")]
    [InlineData("http://localhost:5080/hooks/dmarc")]
    [InlineData("http://[::1]:5080/hooks/dmarc")]
    public async Task PlainHttpToThisMachineIsAllowed(string url)
    {
        var hook = await _store.SetAsync("local", url, Secret, "warning", null, "tester");
        Assert.StartsWith("http://", hook.Destination, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AShortSecretIsRefused()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => _store.SetAsync("local", SlackStyle, "short", "warning", null, "tester"));
        Assert.Contains("openssl rand -hex 32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnknownSeverityIsRefused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _store.SetAsync("local", SlackStyle, Secret, "urgent", null, "tester"));
    }

    [Fact]
    public async Task AnUnknownOrganizationIsRefused()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.SetAsync("nobody", SlackStyle, Secret, "warning", null, "tester"));
    }

    /// <summary>
    /// Install day: the database is new, no report has arrived, so the
    /// built-in organization a report would have created does not exist yet.
    /// Setting up where findings go is exactly what somebody does then.
    /// </summary>
    [Fact]
    public async Task TheBuiltInOrganizationNeedNotHaveHadAReportYet()
    {
        var fresh = Path.Combine(Path.GetTempPath(), $"dmarc-webhooks-fresh-{Guid.NewGuid():N}.db");
        try
        {
            await new ReportStore(fresh).InitializeAsync(DatabaseSchema.Sql);
            var store = new WebhookStore(fresh, _secrets);

            var hook = await store.SetAsync("local", SlackStyle, Secret, "warning", null, "tester");

            Assert.Equal("local", hook.TenantSlug);
            Assert.Equal("Local", Assert.Single(await new OrganizationStore(fresh).ListAsync()).Name);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.SetAsync("nobody", SlackStyle, Secret, "warning", null, "tester"));
        }
        finally
        {
            SingleDatabase.Delete(fresh);
        }
    }

    /// <summary>
    /// Replacing keeps the webhook's identity - and so its record of what was
    /// sent - and never leaves the old key behind in the store.
    /// </summary>
    [Fact]
    public async Task SettingAgainReplacesTheKeyAndKeepsTheHistory()
    {
        var first = await _store.SetAsync("local", SlackStyle, Secret, "warning", null, "tester");
        var second = await _store.SetAsync("local", "https://console.example/api/sources/dmarc-monitor/events", Secret + "-2", "critical", null, "tester");

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(first.CreatedAt, second.CreatedAt);
        Assert.NotEqual(first.CredentialRef, second.CredentialRef);
        Assert.Null(await _secrets.GetAsync(first.CredentialRef));
        Assert.Equal("critical", second.MinSeverity);
        Assert.Single(await _store.ListAsync());
    }

    [Fact]
    public async Task RemovingForgetsTheKeyToo()
    {
        var hook = await _store.SetAsync("local", SlackStyle, Secret, "warning", null, "tester");

        Assert.True(await _store.RemoveAsync("local", "tester"));
        Assert.Null(await _store.GetAsync("local"));
        Assert.Null(await _secrets.GetAsync(hook.CredentialRef));
        Assert.False(await _store.RemoveAsync("local", "tester"));
    }

    /// <summary>Pointing client data somewhere new is exactly what somebody asks about later.</summary>
    [Fact]
    public async Task EveryChangeIsInTheAuditLog()
    {
        await _store.SetAsync("local", SlackStyle, Secret, "warning", null, "alice");
        await _store.SetAsync("local", "https://console.example/hook", Secret, "warning", null, "bob");
        await _store.RemoveAsync("local", "carol");

        var entries = await new AuditLog(_dbPath).ListAsync();
        Assert.Contains(entries, e => e.Action == "webhook.set" && e.Actor == "alice");
        Assert.Contains(entries, e => e.Action == "webhook.replace" && e.Actor == "bob" && e.Detail!.Contains("https://console.example", StringComparison.Ordinal));
        Assert.Contains(entries, e => e.Action == "webhook.remove" && e.Actor == "carol");

        // The audit trail is readable by more people than the secret store, so
        // it gets the display form only.
        Assert.DoesNotContain(entries, e => e.Detail?.Contains("XyZtOkEn", StringComparison.Ordinal) == true);
    }
}
