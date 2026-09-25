using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// The reverse-name cache.
///
/// It exists because the Sources page was a list of addresses, and every line
/// of it was research somebody had to go and do - with the same answer every
/// time for the same address. "192.3.180.38 against two clients" is homework;
/// "ColoCrossing against two clients" is a finding.
/// </summary>
public sealed class SourceNameStoreTests : IAsyncLifetime
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-names-{Guid.NewGuid():N}.db");

    private SourceNameStore _store = null!;

    public async Task InitializeAsync()
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);
        _store = new SourceNameStore(_dbPath);
    }

    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task RemembersWhatAnAddressReversesTo()
    {
        await _store.SaveAsync("35.174.145.124", "us.cloud-sec-av.com", answered: true);

        var found = await _store.GetAsync(["35.174.145.124"]);

        Assert.True(found.TryGetValue("35.174.145.124", out var row));
        Assert.Equal("us.cloud-sec-av.com", row!.ReverseName);
    }

    /// <summary>
    /// The whole point: the catalogue turns the reverse name into something a
    /// person recognizes, and the operator reads a vendor rather than a host.
    /// </summary>
    [Fact]
    public async Task ACachedReverseNameBecomesAVendorName()
    {
        await _store.SaveAsync("35.174.145.124", "us.cloud-sec-av.com", answered: true);

        var row = (await _store.GetAsync(["35.174.145.124"]))["35.174.145.124"];

        Assert.True(row.IsNamed);
        Assert.DoesNotContain("35.174", row.Display, StringComparison.Ordinal);
    }

    /// <summary>
    /// The honest fallback, and the one that must never be worse than what the
    /// page did before any of this existed.
    /// </summary>
    [Fact]
    public async Task AnAddressWithNoNameStillPrintsAsItself()
    {
        await _store.SaveAsync("203.0.113.7", null, answered: true);

        var row = (await _store.GetAsync(["203.0.113.7"]))["203.0.113.7"];

        Assert.False(row.IsNamed);
        Assert.Equal("203.0.113.7", row.Display);
    }

    /// <summary>
    /// A reverse name the catalogue has never heard of is still better than
    /// digits: it is at least a domain somebody can search for.
    /// </summary>
    [Fact]
    public async Task AnUnrecognizedReverseNameIsShownRatherThanDiscarded()
    {
        await _store.SaveAsync("198.51.100.9", "mail07.some-small-isp.example", answered: true);

        var row = (await _store.GetAsync(["198.51.100.9"]))["198.51.100.9"];

        Assert.Equal("mail07.some-small-isp.example", row.Display);
        Assert.True(row.IsNamed);
    }

    [Fact]
    public async Task LookingUpAgainReplacesTheAnswerRatherThanAddingOne()
    {
        await _store.SaveAsync("192.0.2.1", "old.example", answered: true);
        await _store.SaveAsync("192.0.2.1", "new.example", answered: true);

        var found = await _store.GetAsync(["192.0.2.1"]);

        Assert.Single(found);
        Assert.Equal("new.example", found["192.0.2.1"].ReverseName);
    }

    [Fact]
    public async Task AnAddressNobodyHasLookedUpIsSimplyAbsent()
    {
        var found = await _store.GetAsync(["192.0.2.99"]);

        Assert.Empty(found);
    }

    /// <summary>
    /// SQLite refuses a statement with more than 999 parameters, and an estate
    /// with a thousand sources is not unusual - so the read chunks. Asking for
    /// more than the limit must return everything rather than throwing, which
    /// is the failure a busy install would have hit and a small one never
    /// would.
    /// </summary>
    [Fact]
    public async Task ReadsMoreAddressesThanSqliteWillTakeParametersFor()
    {
        var addresses = Enumerable.Range(0, 1200).Select(i => $"10.1.{i / 256}.{i % 256}").ToList();
        foreach (var ip in addresses) { await _store.SaveAsync(ip, $"host-{ip}.example", answered: true); }

        var found = await _store.GetAsync(addresses);

        Assert.Equal(addresses.Count, found.Count);
    }

    [Fact]
    public async Task AsksForNothingWhenGivenNothing()
    {
        Assert.Empty(await _store.GetAsync([]));
    }
}
