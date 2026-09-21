using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// Applying a plan to a zone, and the record of having done so.
///
/// Every guardrail here exists because the alternative broke somebody's mail
/// once: writing over a value the plan never saw, recording a change that was
/// only asked for, rolling back to what the plan thought was there rather
/// than what was. The zone is in memory; the database is real.
/// </summary>
public sealed class RemediationServiceTests : IDisposable
{
    private const string Domain = "dmvwrr.com";
    private const string Name = "_dmarc.dmvwrr.com";
    private const string Before = "v=DMARC1; p=none; rua=mailto:dmarc@dmvwrr.com";
    private const string After = "v=DMARC1; p=quarantine; rua=mailto:dmarc@dmvwrr.com";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-fix-{Guid.NewGuid():N}.db");
    private readonly RemediationService _service;
    private readonly InMemoryDnsProvider _zone = new();

    public RemediationServiceTests()
    {
        var store = new ReportStore(_dbPath);
        store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();

        // A real report, so the domain exists the way it would in production:
        // filed under a client, with ids the audit rows need.
        var xml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dmv-google-aggregate.xml"));
        store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, null).GetAwaiter().GetResult();

        _service = new RemediationService(_dbPath);
        _zone.Add(Name, "TXT", Before);
        _zone.Add(Domain, "TXT", "v=spf1 include:spf.protection.outlook.com -all");
        _zone.Add(Domain, "TXT", "MS=ms12345678");
    }

    /// <summary>
    /// A zone that breaks the way a real one does: the network drops.
    /// </summary>
    /// <remarks>
    /// CloudflareDnsProvider has no exception handling of its own, so an
    /// HttpRequestException from a write travels straight out of the provider.
    /// This stands in for that.
    /// </remarks>
    private sealed class ThrowingZone(InMemoryDnsProvider inner, bool onRead, bool onWrite) : IDnsProvider
    {
        public string Name => "throwing";
        public bool CanWrite => true;
        public int Reads { get; private set; }

        public Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default)
        {
            Reads++;
            // The FIRST read is the snapshot and was always guarded; the
            // second, immediately before the write, was not.
            return onRead && Reads > 1
                ? throw new HttpRequestException("connection reset by peer")
                : inner.GetRecordsAsync(name, type, ct);
        }

        public Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default) =>
            onWrite
                ? throw new HttpRequestException("the connection was closed after the request was sent")
                : inner.SetRecordAsync(write, ct);

        public Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default) =>
            inner.RemoveRecordAsync(record, ct);
    }

    [Fact]
    public async Task AReadThatFailsJustBeforeTheWriteIsNotAppliedAndNotACrash()
    {
        // This read was the only provider call on the apply path with nothing
        // around it, so a dropped connection here left the method entirely and
        // reached the operator as a stack trace under "This is a bug".
        var zone = new ThrowingZone(_zone, onRead: true, onWrite: false);
        var plan = DmarcPolicyPlanner.Advance(Domain, Before, "quarantine");

        var outcome = await _service.ApplyAsync(plan, zone, confirm: true, "tester", "because");

        Assert.False(outcome.Applied);
        Assert.Contains("could not be read", outcome.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal([Before], _zone.ValuesAt(Name));
    }

    [Fact]
    public async Task AWriteThatMayOrMayNotHaveLandedNeverClaimsNothingHappened()
    {
        // A connection dropped after the request left is indistinguishable
        // from one that never arrived, and a timeout is precisely the case
        // where the write most likely DID happen. "Not applied" is the one
        // answer that would certainly be unsafe, so it must not say that -
        // and it has to carry the previous value, since an operator checking
        // the zone by hand needs to know what it should have held.
        var zone = new ThrowingZone(_zone, onRead: false, onWrite: true);
        var plan = DmarcPolicyPlanner.Advance(Domain, Before, "quarantine");

        var outcome = await _service.ApplyAsync(plan, zone, confirm: true, "tester", "because");

        Assert.False(outcome.Applied);
        Assert.DoesNotContain("Not applied", outcome.Message, StringComparison.Ordinal);
        Assert.Contains("unknown", outcome.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(Before, outcome.Message, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static ChangePlan Advance() => DmarcPolicyPlanner.Advance(Domain, Before, "quarantine");

    // ---- what it refuses ----------------------------------------------------

    [Fact]
    public async Task ADryRunWritesNothingAndSaysWhatItWouldDo()
    {
        var outcome = await _service.ApplyAsync(Advance(), _zone, confirm: false, "tester", "test");

        Assert.True(outcome.DryRun);
        Assert.False(outcome.Applied);
        Assert.Equal(Before, outcome.Snapshot);
        Assert.Empty(_zone.Log);
        Assert.Contains("Would move", outcome.Message, StringComparison.Ordinal);

        // Looked, and recorded having looked.
        Assert.NotNull(outcome.PlanId);
    }

    [Fact]
    public async Task AnUnsafePlanIsNeverAppliedEvenWithConfirmation()
    {
        // There is no flag that overrides a blocker. The whole reason it is
        // a blocker is that somebody would eventually use the flag.
        var refused = DmarcPolicyPlanner.Advance(Domain, Before, "reject");

        var outcome = await _service.ApplyAsync(refused, _zone, confirm: true, "tester", "test");

        Assert.False(outcome.Applied);
        Assert.NotEmpty(outcome.Error);
        Assert.Empty(_zone.Log);
        Assert.Equal([Before], _zone.ValuesAt(Name));
    }

    [Fact]
    public async Task ANoopWritesNothing()
    {
        var noop = DmarcPolicyPlanner.Advance(Domain, Before, "none");

        var outcome = await _service.ApplyAsync(noop, _zone, confirm: true, "tester", "test");

        Assert.False(outcome.Applied);
        Assert.Empty(outcome.Error);
        Assert.Empty(_zone.Log);
    }

    [Fact]
    public async Task RefusesToWriteOverAValueThePlanNeverSaw()
    {
        // The plan was made against p=none. Somebody has since set
        // p=reject by hand. Applying the plan would silently weaken it.
        var plan = Advance();
        await _zone.SetRecordAsync(new DnsRecordWrite(Name, "TXT", "v=DMARC1; p=reject", ReplacesValue: Before));
        _zone.Log.Clear();

        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "test");

        Assert.False(outcome.Applied);
        Assert.Contains("changed after this plan was made", outcome.Error, StringComparison.Ordinal);
        Assert.Empty(_zone.Log);
    }

    [Fact]
    public async Task AManualZoneIsToldWhatToPublishAndNothingIsRecordedAsDone()
    {
        var manual = new ManualDnsProvider();   // never queried here: the domain is not real

        var outcome = await _service.ApplyAsync(
            DmarcPolicyPlanner.Advance("nowhere.invalid", Before, "quarantine"), manual, confirm: true, "tester", "test");

        // Not in the database, so refused before any lookup.
        Assert.False(outcome.Applied);
        Assert.Contains("not a domain this has reports for", outcome.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainWithNoReportsIsNotOneItWillWriteTo()
    {
        var outcome = await _service.ApplyAsync(
            DmarcPolicyPlanner.Advance("stranger.example", Before, "quarantine"), _zone, confirm: true, "tester", "test");

        Assert.False(outcome.Applied);
        Assert.Null(outcome.PlanId);
        Assert.Empty(_zone.Log);
    }

    // ---- what it does ------------------------------------------------------

    [Fact]
    public async Task AppliesReplacingOnlyTheRecordThePlanIsAbout()
    {
        var outcome = await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "advance after 30 days clean");

        Assert.True(outcome.Applied);
        Assert.NotNull(outcome.ChangeId);
        Assert.Equal([After], _zone.ValuesAt(Name));

        // The apex was not touched.
        Assert.Equal(2, _zone.ValuesAt(Domain).Count);
    }

    [Fact]
    public async Task TheAuditRowCarriesTheLiveValueNotThePlansIdeaOfIt()
    {
        // The plan says p=none. The zone says the same, but with different
        // spacing, as a control panel would have saved it. previous_value
        // must be what the zone held, because that is what rollback writes.
        const string asSaved = "v=DMARC1;p=none;rua=mailto:dmarc@dmvwrr.com";
        await _zone.SetRecordAsync(new DnsRecordWrite(Name, "TXT", asSaved, ReplacesValue: Before));
        var plan = DmarcPolicyPlanner.Advance(Domain, asSaved, "quarantine");

        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "test");
        var change = await _service.GetChangeAsync(outcome.ChangeId!);

        Assert.NotNull(change);
        Assert.Equal(asSaved, change.PreviousValue);
        Assert.Equal(plan.ProposedValue, change.NewValue);
        Assert.Equal("tester", change.AppliedBy);
        Assert.Equal("test", change.Reason);
        Assert.Equal("memory", change.Provider);
        Assert.False(change.IsPropagated);
    }

    [Fact]
    public async Task AppliedTwiceIsAppliedOnce()
    {
        await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "test");
        var again = await _service.ApplyAsync(DmarcPolicyPlanner.Advance(Domain, After, "quarantine"), _zone, confirm: true, "tester", "test");

        Assert.False(again.Applied);
        Assert.Empty(again.Error);
        Assert.Single(_zone.Log);
        Assert.Single(await _service.HistoryAsync(Domain));
    }

    [Fact]
    public async Task RollsBackToTheSnapshotAndRecordsWhoAndWhy()
    {
        var applied = await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "test");

        var undone = await _service.RollBackAsync(applied.ChangeId!, _zone, "tester", "customer's newsletter went to junk");

        Assert.True(undone.Applied);
        Assert.Equal([Before], _zone.ValuesAt(Name));

        var change = await _service.GetChangeAsync(applied.ChangeId!);
        Assert.NotNull(change!.RolledBackAt);
        Assert.Equal("customer's newsletter went to junk", change.RollbackReason);
    }

    [Fact]
    public async Task WillNotRollBackTwice()
    {
        // Writing the old value again over whatever came after the first
        // rollback is a new change dressed as an undo.
        var applied = await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "test");
        await _service.RollBackAsync(applied.ChangeId!, _zone, "tester", "first");

        var again = await _service.RollBackAsync(applied.ChangeId!, _zone, "tester", "second");

        Assert.False(again.Applied);
        Assert.Contains("already rolled back", again.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WillNotRollBackOverSomebodyElsesLaterChange()
    {
        var applied = await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "test");
        await _zone.SetRecordAsync(new DnsRecordWrite(Name, "TXT", "v=DMARC1; p=reject", ReplacesValue: After));

        var undone = await _service.RollBackAsync(applied.ChangeId!, _zone, "tester", "test");

        Assert.False(undone.Applied);
        Assert.Contains("no longer at", undone.Error, StringComparison.Ordinal);
        Assert.Equal(["v=DMARC1; p=reject"], _zone.ValuesAt(Name));
    }

    [Fact]
    public async Task RollingBackACreationRemovesTheRecord()
    {
        await _zone.RemoveRecordAsync((await _zone.GetRecordsAsync(Name, "TXT"))[0]);
        var created = await _service.ApplyAsync(DmarcPolicyPlanner.Advance(Domain, "", "none"), _zone, confirm: true, "tester", "test");
        Assert.True(created.Applied);

        var undone = await _service.RollBackAsync(created.ChangeId!, _zone, "tester", "test");

        Assert.True(undone.Applied);
        Assert.Empty(_zone.ValuesAt(Name));
    }

    [Fact]
    public async Task AChangeIsFoundByThePrefixAnOperatorReadsOffAScreen()
    {
        var applied = await _service.ApplyAsync(Advance(), _zone, confirm: true, "tester", "test");

        var change = await _service.GetChangeAsync(applied.ChangeId![..8]);

        Assert.Equal(applied.ChangeId, change?.Id);
    }

    [Fact]
    public async Task SpfChangesLandOnTheSpfRecordNotTheVerificationToken()
    {
        // Three TXT records at the apex; the plan is about one of them.
        const string spf = "v=spf1 include:spf.protection.outlook.com -all";
        await _zone.SetRecordAsync(new DnsRecordWrite(Domain, "TXT", spf + " include:dead.example", ReplacesValue: spf));
        var plan = SpfIncludePlanner.RemoveDeadInclude(Domain, spf + " include:dead.example", "dead.example");

        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "test");

        Assert.True(outcome.Applied);
        Assert.Contains("MS=ms12345678", _zone.ValuesAt(Domain));
        Assert.Contains(spf, _zone.ValuesAt(Domain));
        Assert.Equal(2, _zone.ValuesAt(Domain).Count);
    }

    // ---- one record of a kind, never two ------------------------------------

    /// <summary>
    /// A plan to create a record, built when the zone held none.
    /// </summary>
    private static ChangePlan Create(string type, string name, string proposed) => new()
    {
        Domain = Domain,
        Type = type,
        RecordName = name,
        RecordType = "TXT",
        CurrentValue = "",
        ProposedValue = proposed,
        Summary = $"Publish {name}",
    };

    [Fact]
    public async Task ATlsReportingRecordThatAppearedSinceThePlanIsReplacedNotDuplicated()
    {
        // RFC 8460 section 3: if the number of TLS-RPT records is not one,
        // senders MUST assume the domain has no TLS-RPT policy. Writing a
        // second one does not add reporting, it ends it.
        //
        // The plan is built when the name is empty, so it carries no current
        // value; somebody publishes a record before it is applied. The apply
        // path has to notice that and replace.
        const string name = "_smtp._tls.dmvwrr.com";
        _zone.Add(name, "TXT", "v=TLSRPTv1; rua=mailto:old@dmvwrr.com");

        var outcome = await _service.ApplyAsync(
            Create(ChangeType.TlsRpt, name, "v=TLSRPTv1; rua=mailto:dmarc@nrgtechservices.com"),
            _zone, confirm: true, "tester", "test");

        Assert.True(outcome.Applied, outcome.Error);
        Assert.Single(_zone.ValuesAt(name));
    }

    [Fact]
    public async Task AnMtaStsRecordThatAppearedSinceThePlanIsReplacedNotDuplicated()
    {
        // RFC 8461 section 3.1: two TXT records at _mta-sts leave a sender
        // unable to tell which policy id is current, and senders cache the
        // failure for max_age - so the breakage outlives the mistake.
        const string name = "_mta-sts.dmvwrr.com";
        _zone.Add(name, "TXT", "v=STSv1; id=20260101000000");

        var outcome = await _service.ApplyAsync(
            Create(ChangeType.MtaSts, name, "v=STSv1; id=20260918120000"),
            _zone, confirm: true, "tester", "test");

        Assert.True(outcome.Applied, outcome.Error);
        Assert.Single(_zone.ValuesAt(name));
    }

    [Fact]
    public async Task ADmarcRecordThatAppearedSinceThePlanIsStillReplacedNotDuplicated()
    {
        // The case that was already handled, kept so the fix for the two above
        // cannot regress it.
        const string name = "_dmarc.other.example";
        _zone.Add(name, "TXT", "v=DMARC1; p=none");

        var outcome = await _service.ApplyAsync(
            Create(ChangeType.DmarcPolicy, name, "v=DMARC1; p=quarantine"),
            _zone, confirm: true, "tester", "test");

        Assert.True(outcome.Applied, outcome.Error);
        Assert.Single(_zone.ValuesAt(name));
    }

    [Fact]
    public async Task AVerificationTokenSharingTheNameIsNotMistakenForTheRecord()
    {
        // The reason this matches by kind rather than by "whatever is there".
        // An apex holds many TXT records and a plan touches exactly one.
        _zone.Add(Domain, "TXT", "google-site-verification=abc123");

        var before = _zone.ValuesAt(Domain).Count;

        var outcome = await _service.ApplyAsync(
            Create(ChangeType.TlsRpt, Domain, "v=TLSRPTv1; rua=mailto:dmarc@nrgtechservices.com"),
            _zone, confirm: true, "tester", "test");

        Assert.True(outcome.Applied, outcome.Error);
        Assert.Contains("google-site-verification=abc123", _zone.ValuesAt(Domain));
        Assert.Equal(before + 1, _zone.ValuesAt(Domain).Count);
    }
}
