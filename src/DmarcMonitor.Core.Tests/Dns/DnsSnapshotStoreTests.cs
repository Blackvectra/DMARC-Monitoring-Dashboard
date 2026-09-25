using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Storing what a domain was seen to publish, against the real schema.
///
/// Two properties carry the weight here. A reading that failed must not be
/// stored as a domain that publishes nothing, because the newest snapshot is
/// what every screen reads as the truth. And a reading identical to the last
/// one must not create a second row, because the table is content-addressed
/// and its history is meant to be one row per state the domain has really
/// been in.
/// </summary>
public sealed class DnsSnapshotStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-dns-{Guid.NewGuid():N}.db");
    private readonly DnsSnapshotStore _store;

    public DnsSnapshotStoreTests()
    {
        var reports = new ReportStore(_dbPath);
        reports.InitializeAsync(File.ReadAllText(FindSchema())).GetAwaiter().GetResult();

        // A domain only exists once a report has arrived for it, which is how
        // the rest of the product works: nothing is onboarded by hand first.
        var xml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "google-aggregate.xml"));
        reports.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, "msg-1")
            .GetAwaiter().GetResult();

        _store = new DnsSnapshotStore(_dbPath);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    private static string FindSchema()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "db", "schema.sql");
            if (File.Exists(candidate)) { return candidate; }
        }
        throw new FileNotFoundException("Could not find db/schema.sql from the test output directory.");
    }

    /// <summary>The domain the fixture report is about.</summary>
    private async Task<string> DomainAsync()
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText = "SELECT name FROM domains LIMIT 1";
        return (string)(await command.ExecuteScalarAsync())!;
    }

    private static PublishedRecords Good(string domain) => new()
    {
        Domain = domain,
        SpfRecords = ["v=spf1 include:_spf.example.net -all"],
        DmarcRecord = "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@example.net",
        SpfLookups = 4,
    };

    /// <summary>
    /// A changed reading records what changed, and the record can be
    /// acknowledged - once, by somebody in the same organization.
    /// </summary>
    [Fact]
    public async Task AChangedReadingIsRecordedAsDriftAndCanBeAcknowledged()
    {
        var domain = await DomainAsync();
        var first = await _store.SaveAsync(domain, Good(domain));
        Assert.Empty(first.Drift);

        var weaker = Good(domain) with { DmarcRecord = "v=DMARC1; p=none; rua=mailto:d@example.net" };
        var second = await _store.SaveAsync(domain, weaker);

        Assert.True(second.Changed);
        var change = Assert.Single(second.Drift);
        Assert.Equal("critical", change.Severity);

        var drift = new DnsDriftStore(_dbPath);
        var stored = Assert.Single(await drift.ListAsync(tenantId: null, openOnly: true));
        Assert.Equal(domain, stored.Domain);
        Assert.Equal(change.Summary, stored.Summary);
        Assert.False(stored.WasExpected);

        Assert.False(await drift.AcknowledgeAsync(stored.Id, "someone@else", null, tenantId: "another-organization"));
        Assert.True(await drift.AcknowledgeAsync(stored.Id, "tech@msp.example", "client moved registrar", tenantId: null));
        Assert.False(await drift.AcknowledgeAsync(stored.Id, "tech@msp.example", null, tenantId: null));

        Assert.Empty(await drift.ListAsync(tenantId: null, openOnly: true));
        var seen = Assert.Single(await drift.ListAsync(tenantId: null, domain: domain));
        Assert.Equal("tech@msp.example", seen.AcknowledgedBy);
        Assert.Equal("client moved registrar", seen.Note);
    }

    /// <summary>
    /// A first reading is a first reading, not "nothing changed": a fresh
    /// install scanning its domains was told nothing had changed since
    /// readings that did not exist.
    /// </summary>
    [Fact]
    public async Task AFirstReadingSaysSo()
    {
        var domain = await DomainAsync();

        Assert.True((await _store.SaveAsync(domain, Good(domain))).First);
        Assert.False((await _store.SaveAsync(domain, Good(domain))).First);
    }

    [Fact]
    public async Task AnUnchangedReadingRecordsNoDrift()
    {
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, Good(domain));
        await _store.SaveAsync(domain, Good(domain));

        Assert.Empty(await new DnsDriftStore(_dbPath).ListAsync(tenantId: null));
    }

    [Fact]
    public async Task StoresAReadingAndReadsItBack()
    {
        var domain = await DomainAsync();

        // Not a change: there was nothing to differ from. Calling the first
        // reading of a domain a change would fire "this domain's DNS was
        // edited" at every newly onboarded customer.
        Assert.Equal(new SnapshotSave(Stored: true, Changed: false) { First = true }, await _store.SaveAsync(domain, Good(domain)));

        var all = await _store.LatestAsync();
        var dns = all[domain];

        Assert.Equal(DnsCheckStatus.Ok, dns.Status);
        Assert.Equal("v=spf1 include:_spf.example.net -all", dns.SpfRecord);
        Assert.Equal(1, dns.SpfRecordCount);
        Assert.Equal(4, dns.SpfLookups);
        Assert.Equal("-all", dns.SpfAll);
        Assert.Equal("quarantine", dns.DmarcPolicy);
        Assert.Equal("mailto:d@example.net", dns.DmarcRua);
        Assert.NotNull(dns.CheckedAt);
        Assert.NotNull(dns.CapturedAt);
    }

    [Fact]
    public async Task AnUnchangedReadingDoesNotBecomeASecondRow()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Good(domain));
        Assert.False((await _store.SaveAsync(domain, Good(domain))).Changed);

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));
    }

    [Fact]
    public async Task ADomainThatRevertsToAnOldRecordStillReadsAsPublishingIt()
    {
        // The case the content-addressed table gets wrong if "latest" is
        // picked by when a row was first written. Going back to a record
        // inserts nothing - that row is already there, carrying the date it
        // first appeared - so ordering by that date would name the abandoned
        // record as the current one, and every chip would describe DNS the
        // domain no longer publishes.
        var domain = await DomainAsync();
        var first = Good(domain);
        var second = Good(domain) with { DmarcRecord = "v=DMARC1; p=reject; rua=mailto:d@example.net" };

        await _store.SaveAsync(domain, first);
        await _store.SaveAsync(domain, second);
        Assert.True((await _store.SaveAsync(domain, first)).Changed);   // reverting is itself a change

        Assert.Equal(2, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));
        Assert.Equal("quarantine", (await _store.LatestAsync())[domain].DmarcPolicy);
    }

    [Fact]
    public async Task WhichReadingIsCurrentDoesNotDependOnTheClock()
    {
        // The revert case again, with the clock taken out of it. Two readings
        // stored in the same tick are not exotic: a fast machine does three of
        // these inside one millisecond, which is how CI found this when a
        // slower laptop could not. Whatever resolution the timestamp has,
        // something faster than it exists, so ordering must not be decided by
        // a timestamp at all.
        var domain = await DomainAsync();
        var first = Good(domain);
        var second = Good(domain) with { DmarcRecord = "v=DMARC1; p=reject; rua=mailto:d@example.net" };

        await _store.SaveAsync(domain, first);
        await _store.SaveAsync(domain, second);
        await _store.SaveAsync(domain, first);

        // Force the pathological tie rather than waiting to be unlucky: every
        // reading recorded at the same instant, so only the sequence can say
        // which came last.
        await ExecuteAsync("UPDATE dns_snapshots SET last_seen_at = '2026-01-01 00:00:00'");

        Assert.Equal("quarantine", (await _store.LatestAsync())[domain].DmarcPolicy);
    }

    [Fact]
    public async Task AChangedRecordDoesBecomeASecondRow()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Good(domain));
        Assert.True((await _store.SaveAsync(domain, Good(domain) with
        {
            DmarcRecord = "v=DMARC1; p=reject; rua=mailto:d@example.net",
        })).Changed);

        Assert.Equal(2, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));

        var dns = (await _store.LatestAsync())[domain];
        Assert.Equal("reject", dns.DmarcPolicy);
    }

    [Fact]
    public async Task AFailedLookupIsNeverStoredAsADomainThatPublishesNothing()
    {
        // The property this whole feature rests on. The newest snapshot is
        // what the screens read as the truth, and a timeout written into it
        // would turn a five-second network blip into a confident claim that
        // a customer has no DMARC record.
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, Good(domain));

        await _store.SaveAsync(domain, new PublishedRecords { Domain = domain, LookupFailed = true });

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));

        var dns = (await _store.LatestAsync())[domain];

        Assert.Equal(DnsCheckStatus.Failed, dns.Status);
        Assert.Equal("v=spf1 include:_spf.example.net -all", dns.SpfRecord);   // what was last really seen
        Assert.Equal(RecordState.Unreadable, RecordStatus.Spf(dns).State);
    }

    [Fact]
    public async Task ADomainThatDoesNotExistIsRecordedWithoutASnapshot()
    {
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, new PublishedRecords { Domain = domain, DomainDoesNotExist = true });

        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));
        Assert.Equal(DnsCheckStatus.NoSuchDomain, (await _store.LatestAsync())[domain].Status);
    }

    [Fact]
    public async Task ADomainNobodyHasReadComesBackAsNeverChecked()
    {
        var dns = (await _store.LatestAsync())[await DomainAsync()];

        Assert.Equal(DnsCheckStatus.NeverChecked, dns.Status);
        Assert.Null(dns.CheckedAt);
        Assert.False(dns.HasReading);
    }

    [Fact]
    public async Task RecordsTwoSpfRecordsAsTwo()
    {
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, Good(domain) with
        {
            SpfRecords = ["v=spf1 -all", "v=spf1 include:other.example -all"],
        });

        var dns = (await _store.LatestAsync())[domain];

        Assert.Equal(2, dns.SpfRecordCount);
        Assert.Equal(RecordState.Weak, RecordStatus.Spf(dns).State);
    }

    [Fact]
    public async Task FillsInTheDenormalizedPolicyTheSchemaAlwaysHadAndNothingWrote()
    {
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, Good(domain));

        Assert.Equal("quarantine", await ScalarAsync("SELECT current_policy FROM domains LIMIT 1"));
        Assert.Equal(50L, await CountAsync("SELECT current_pct FROM domains LIMIT 1"));
    }

    [Fact]
    public async Task StoresTheSelectorsThatWereLookedUp()
    {
        var domain = await DomainAsync();
        var seen = DateTimeOffset.UtcNow.AddDays(-2);

        await _store.SaveAsync(domain, Good(domain),
        [
            new SelectorReading("live", DkimKey.Parse("live", $"v=DKIM1; p={Key()}"), seen),
            new SelectorReading("gone", DkimKey.Parse("gone", null), seen),
        ]);

        var dns = (await _store.LatestAsync())[domain];

        Assert.Equal(2, dns.DkimSelectors.Count);
        Assert.Contains(dns.DkimSelectors, s => s.Selector == "live" && s.Status == "strong" && s.Bits == 2048);
        Assert.Contains(dns.DkimSelectors, s => s.Selector == "gone" && s.Status == "invalid");
        Assert.Equal(RecordState.Weak, RecordStatus.Dkim(dns).State);
    }

    [Fact]
    public async Task ASelectorLookupThatCouldNotAnswerKeepsWhatWasLastKnown()
    {
        // Null is "could not tell", and it must not overwrite a good reading
        // with an absence nobody observed. Recording the selector as broken
        // on a timeout is the DKIM version of reporting a missing record,
        // and it reads as mail failing at every receiver.
        var domain = await DomainAsync();
        var seen = DateTimeOffset.UtcNow.AddDays(-2);

        await _store.SaveAsync(domain, Good(domain),
            [new SelectorReading("live", DkimKey.Parse("live", $"v=DKIM1; p={Key()}"), seen)]);

        await _store.SaveAsync(domain, Good(domain),
            [new SelectorReading("live", null, DateTimeOffset.UtcNow)]);

        var selector = Assert.Single((await _store.LatestAsync())[domain].DkimSelectors);

        Assert.Equal("strong", selector.Status);
        Assert.Equal(2048, selector.Bits);
    }

    [Fact]
    public async Task AnUnknownSelectorThatCouldNotBeReadIsNotInvented()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Good(domain),
            [new SelectorReading("mystery", null, DateTimeOffset.UtcNow)]);

        Assert.Empty((await _store.LatestAsync())[domain].DkimSelectors);
    }

    [Fact]
    public async Task ASelectorNotSeenSigningRecentlyStopsCounting()
    {
        // dkim_selectors rows are never deleted, so without the window a
        // selector retired two years ago would be drawn as a broken key
        // forever.
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Good(domain),
            [new SelectorReading("ancient", DkimKey.Parse("ancient", null), DateTimeOffset.UtcNow.AddDays(-400))]);

        Assert.Empty((await _store.LatestAsync(selectorDays: 30))[domain].DkimSelectors);
        Assert.Single((await _store.LatestAsync(selectorDays: 500))[domain].DkimSelectors);
    }

    [Fact]
    public async Task ADomainThatIsNotInTheBookIsNotInvented()
    {
        // Checking a prospect's domain before they are a customer is the
        // commonest use of 'dmarc check', and there is no domain row to hang a
        // reading off until reports for it arrive. Saying so beats inventing a
        // customer, and beats a command reporting that it stored something it
        // quietly dropped.
        var save = await _store.SaveAsync("nobody-asked-about-this.example", Good("nobody-asked-about-this.example"));

        Assert.False(save.Stored);
        Assert.False(save.Changed);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));
    }

    [Fact]
    public async Task ScopesToTheOrganizationAsked()
    {
        var domain = await DomainAsync();
        await _store.SaveAsync(domain, Good(domain));

        Assert.Empty(await _store.LatestAsync(tenantId: "an-organization-that-does-not-exist"));
        Assert.NotEmpty(await _store.LatestAsync());
    }

    /// <summary>
    /// The mode of the served policy is stored, because DNS cannot answer it.
    /// </summary>
    /// <remarks>
    /// mta_sts_record carries an id and nothing else; the mode lives in a file
    /// fetched over HTTPS. Without this column a snapshot can say a domain
    /// announces a policy and cannot say whether that policy requires
    /// anything, and a policy in testing requires nothing at all.
    /// </remarks>
    [Fact]
    public async Task RemembersWhatModeTheServedPolicyWasIn()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Announcing(domain, MtaStsMode.Enforce));

        Assert.Equal(MtaStsMode.Enforce, (await _store.LatestAsync())[domain].MtaStsMode);
    }

    /// <summary>
    /// A domain announcing a policy nobody can fetch is its own state, not an
    /// absent record: the TXT is published, so a sender looks, and finds
    /// nothing it can apply.
    /// </summary>
    [Fact]
    public async Task AnnouncedAndNotServedIsRecordedAsSuch()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Announcing(domain, mode: null));

        Assert.Equal("unreachable", (await _store.LatestAsync())[domain].MtaStsMode);
    }

    /// <summary>
    /// A reading taken by something that does not fetch must not erase a mode
    /// that was really observed.
    /// </summary>
    /// <remarks>
    /// Both callers that store readings fetch the policy now, but only for a
    /// domain that announces one, and nothing stops an offline caller storing
    /// a reading. Overwriting enforce with "we did not look" would have the
    /// table say a protected domain stopped being protected on the day
    /// somebody ran a scan that makes no HTTPS requests.
    /// </remarks>
    [Fact]
    public async Task AReadingThatDidNotFetchLeavesTheKnownModeAlone()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Announcing(domain, MtaStsMode.Enforce));
        await _store.SaveAsync(domain, Announcing(domain, mode: null) with { ServedMtaSts = null });

        Assert.Equal(MtaStsMode.Enforce, (await _store.LatestAsync())[domain].MtaStsMode);
    }

    /// <summary>
    /// The served mode is not part of the content hash, so observing it does
    /// not insert a row and does not report that the zone was edited.
    /// </summary>
    /// <remarks>
    /// The file is fetched over HTTPS from a host that can time out on its
    /// own schedule. Hashing it would let one flaky minute of network announce
    /// a DNS change to somebody who would then go looking for an edit that
    /// never happened.
    /// </remarks>
    [Fact]
    public async Task APolicyThatBecameUnreachableIsNotADnsChange()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Announcing(domain, MtaStsMode.Enforce));
        var again = await _store.SaveAsync(domain, Announcing(domain, mode: null));

        Assert.False(again.Changed);
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM dns_snapshots"));
        Assert.Equal("unreachable", (await _store.LatestAsync())[domain].MtaStsMode);
    }

    [Fact]
    public async Task CarriesTheTransportRecordsBackOutOfTheDatabase()
    {
        var domain = await DomainAsync();

        await _store.SaveAsync(domain, Announcing(domain, MtaStsMode.Testing));

        var read = (await _store.LatestAsync())[domain];
        Assert.Equal("v=STSv1; id=20260101000000Z", read.MtaStsRecord);
        Assert.Equal("v=TLSRPTv1; rua=mailto:tls@example.net", read.TlsRptRecord);
    }

    /// <summary>A domain publishing both transport records, serving the given mode.</summary>
    /// <param name="mode">Null for a policy that was asked for and could not be had.</param>
    private static PublishedRecords Announcing(string domain, string? mode) => Good(domain) with
    {
        MtaStsRecord = "v=STSv1; id=20260101000000Z",
        TlsRptRecord = "v=TLSRPTv1; rua=mailto:tls@example.net",
        ServedMtaSts = mode is null
            ? ServedPolicy.Missing("there is no file there")
            : new ServedPolicy(true, new MtaStsPolicy
            {
                Mode = mode,
                Mx = ["mx.example.net"],
                MaxAgeSeconds = MtaStsPolicy.DefaultMaxAgeSeconds,
                Id = "20260101000000Z",
            }, null),
    };

    private static string Key()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        return Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
    }

    /// <summary>SQL written for one database, split into client files afterwards.</summary>
    private Task ExecuteAsync(string sql) => SingleDatabase.ExecuteAsync(_dbPath, sql);

    private async Task<long> CountAsync(string sql) =>
        Convert.ToInt64(await RawAsync(sql), System.Globalization.CultureInfo.InvariantCulture);

    private async Task<string?> ScalarAsync(string sql) => await RawAsync(sql) as string;

    /// <summary>Read across the organization's database and every client's file.</summary>
    private Task<object?> RawAsync(string sql) => SingleDatabase.ScalarAsync(_dbPath, sql);
}
