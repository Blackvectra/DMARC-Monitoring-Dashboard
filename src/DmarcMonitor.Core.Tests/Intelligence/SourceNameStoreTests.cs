using DmarcMonitor.Core.Aggregate;
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
        await _store.SaveAsync("35.174.145.124", "us.cloud-sec-av.com", answered: true, forwardConfirmed: true);

        var row = (await _store.GetAsync(["35.174.145.124"]))["35.174.145.124"];

        Assert.True(row.IsNamed);
        Assert.Equal("Avanan (Check Point Harmony)", row.Display);
    }

    /// <summary>
    /// Only once the name points back. A PTR is written by whoever holds the
    /// address, so an unconfirmed one is printed as the hostname it claims:
    /// "Avanan" would be this product vouching for it.
    /// </summary>
    [Fact]
    public async Task AnUnconfirmedNameIsPrintedAsTheHostnameItClaims()
    {
        await _store.SaveAsync("203.0.113.66", "us.cloud-sec-av.com", answered: true, forwardConfirmed: false);

        var row = (await _store.GetAsync(["203.0.113.66"]))["203.0.113.66"];

        Assert.Equal("us.cloud-sec-av.com", row.Display);
        Assert.False(row.ForwardConfirmed);
    }

    [Fact]
    public async Task RemembersWhetherTheNameWasConfirmed()
    {
        await _store.SaveAsync("192.0.2.1", "a.example", answered: true, forwardConfirmed: true);
        await _store.SaveAsync("192.0.2.2", "b.example", answered: true, forwardConfirmed: false);
        await _store.SaveAsync("192.0.2.3", "c.example", answered: true);
        await _store.SaveAsync("192.0.2.4", null, answered: true, forwardConfirmed: true);

        var found = await _store.GetAsync(["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]);

        Assert.True(found["192.0.2.1"].ForwardConfirmed);
        Assert.False(found["192.0.2.2"].ForwardConfirmed);
        Assert.Null(found["192.0.2.3"].ForwardConfirmed);
        // Nothing to confirm without a name.
        Assert.Null(found["192.0.2.4"].ForwardConfirmed);
    }

    /// <summary>
    /// A name stored before confirmation existed is asked again at once, even
    /// though it is fresh. Until it is confirmed it decides nothing, so a
    /// gateway that used to be recognized would be judged without its name.
    /// </summary>
    [Fact]
    public async Task ANameThatWasNeverCheckedIsLookedUpAgain()
    {
        await StoreRowsAsync("192.0.2.50", "192.0.2.51", "192.0.2.52");
        await _store.SaveAsync("192.0.2.50", "never-checked.example", answered: true);
        await _store.SaveAsync("192.0.2.51", "checked.example", answered: true, forwardConfirmed: false);
        await _store.SaveAsync("192.0.2.52", null, answered: true);

        var due = await _store.NeedingLookupAsync();

        Assert.Equal(["192.0.2.50"], due);
    }

    /// <summary>
    /// What a report cannot recognize yet: failing sources never looked up,
    /// or named but never checked. A report built before the names are in
    /// says so rather than quietly knowing less.
    /// </summary>
    [Fact]
    public async Task CountsTheFailingSourcesNobodyHasCheckedYet()
    {
        await StoreRowsAsync("192.0.2.60", "192.0.2.61", "192.0.2.62", "192.0.2.63");
        await _store.SaveAsync("192.0.2.61", "never-checked.example", answered: true);
        await _store.SaveAsync("192.0.2.62", "checked.example", answered: true, forwardConfirmed: true);
        await _store.SaveAsync("192.0.2.63", null, answered: true);

        var count = await _store.UncheckedFailingSourcesAsync(
            DateTimeOffset.UtcNow.AddDays(-7), DateTimeOffset.UtcNow);

        // 192.0.2.60 was never looked up; 192.0.2.61 has a name nobody checked.
        Assert.Equal(2, count);
    }

    private async Task StoreRowsAsync(params string[] addresses)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var rows = string.Concat(addresses.Select(ip => $"""
            <record>
              <row><source_ip>{ip}</source_ip><count>3</count>
                <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
              <identifiers><header_from>a.example</header_from></identifiers>
              <auth_results><spf><domain>a.example</domain><result>fail</result></spf></auth_results>
            </record>
            """));
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata><org_name>google.com</org_name><report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>a.example</domain><p>none</p><pct>100</pct></policy_published>
              {rows}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await new ReportStore(_dbPath).SaveAggregateAsync(parsed.Report!, xml, null);
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
