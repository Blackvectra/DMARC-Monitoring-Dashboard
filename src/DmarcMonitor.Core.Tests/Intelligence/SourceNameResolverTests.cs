using System.Reflection;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Storage;
using DnsClient;

namespace DmarcMonitor.Core.Tests.Intelligence;

/// <summary>
/// What a run of reverse lookups records, and how that reads afterwards.
///
/// The case that matters most is the machine that cannot reach a resolver: a
/// Windows trial offline, or behind a firewall that drops DNS. Every lookup
/// there comes back with no name, which looks exactly like an address with no
/// reverse record - and an address with none is not asked again for a month.
/// </summary>
public sealed class SourceNameResolverTests : IAsyncLifetime
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-resolver-{Guid.NewGuid():N}.db");

    private SourceNameStore _store = null!;
    private SourceNameResolver _resolver = null!;

    public async Task InitializeAsync()
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);
        _store = new SourceNameStore(_dbPath);
        _resolver = new SourceNameResolver(_store, new DnsLookup(Unreachable.Resolver()));
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

    private static string[] Addresses(int count) =>
        [.. Enumerable.Range(1, count).Select(i => $"192.0.2.{i}")];

    /// <summary>
    /// Ten lookups and not one name is a resolver that did not answer, far
    /// more often than ten addresses that happen to publish nothing. Recorded
    /// as answered they would not be asked again until next month; recorded
    /// as not answered they are asked again tomorrow.
    /// </summary>
    [Fact]
    public async Task ARunThatNamesNothingAtAllIsRecordedAsNotAnswered()
    {
        var addresses = Addresses(10);

        var run = await _resolver.RunAsync(addresses, limit: 40);

        Assert.Equal(10, run.Looked);
        Assert.Equal(0, run.Named);
        Assert.True(run.NothingAnswered);

        var rows = await _store.GetAsync(addresses);
        Assert.Equal(10, rows.Count);
        Assert.All(rows.Values, r => Assert.False(r.Answered));

        // Due again after the retry horizon, not the month.
        Assert.Equal(addresses, await _store.DueAmongAsync(addresses, retryAfter: TimeSpan.FromMinutes(-5)));
    }

    [Fact]
    public async Task ThatIsSaidInPlainWordsRatherThanAsTenAddressesWithNoReverseRecord()
    {
        var run = await _resolver.RunAsync(Addresses(10), limit: 40);

        var said = run.Describe();

        Assert.Contains("none came back with a name", said, StringComparison.Ordinal);
        Assert.Contains("tomorrow", said, StringComparison.Ordinal);
        Assert.DoesNotContain("reverse zone did not answer", said, StringComparison.Ordinal);
    }

    /// <summary>
    /// A handful of addresses with nothing is ordinary, and is not enough to
    /// call the resolver down. Those are recorded as they always were.
    /// </summary>
    [Fact]
    public async Task AFewAddressesWithNoNameAreStillRecordedAsAnswered()
    {
        var addresses = Addresses(3);

        var run = await _resolver.RunAsync(addresses, limit: 40);

        Assert.False(run.NothingAnswered);
        Assert.Contains("3 with no name", run.Describe(), StringComparison.Ordinal);

        var rows = await _store.GetAsync(addresses);
        Assert.All(rows.Values, r => Assert.True(r.Answered));
        Assert.Empty(await _store.DueAmongAsync(addresses, retryAfter: TimeSpan.FromMinutes(-5)));
    }

    [Fact]
    public async Task AnAddressAlreadyNamedIsLeftAloneAndNothingIsLookedUp()
    {
        await _store.SaveAsync("192.0.2.1", "mail.example", answered: true, forwardConfirmed: true);

        var run = await _resolver.RunAsync(["192.0.2.1"], limit: 40);

        Assert.Equal(0, run.Looked);
        Assert.Equal("Every source already has a name; nothing to look up.", run.Describe());
    }

    [Fact]
    public async Task OnlyTheFirstOnesAreLookedUpWhenThereAreMoreThanTheLimit()
    {
        var addresses = Addresses(12);

        var run = await _resolver.RunAsync(addresses, limit: 9);

        Assert.Equal(9, run.Looked);
        Assert.Equal(addresses.Take(9), (await _store.GetAsync(addresses)).Keys.Order(new NumericAddressOrder()));
    }

    /// <summary>192.0.2.2 before 192.0.2.10, which a text sort gets the other way round.</summary>
    private sealed class NumericAddressOrder : IComparer<string>
    {
        public int Compare(string? x, string? y) =>
            int.Parse(x!.Split('.')[^1], System.Globalization.CultureInfo.InvariantCulture)
                .CompareTo(int.Parse(y!.Split('.')[^1], System.Globalization.CultureInfo.InvariantCulture));
    }
}

/// <summary>A resolver that answers nothing: every query fails the way a dead network does.</summary>
public class Unreachable : DispatchProxy
{
    public static ILookupClient Resolver() => Create<ILookupClient, Unreachable>();

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
        throw new DnsResponseException("There is no network in this test.");
}
