using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Findings;

/// <summary>
/// The invariants every finding lives by, whichever engine raised it: one
/// row per condition, resolution only from a successful observation, a
/// person's decision never mistaken for evidence, an exception that hides
/// and never blinds, and one organization unable to reach another's.
/// </summary>
public sealed class FindingLifecycleTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-findings-{Guid.NewGuid():N}.db");
    private readonly TestClock _clock = new();
    private readonly FindingLifecycle _lifecycle;
    private readonly Ids _acme;

    /// <summary>The product's types plus one a test anomaly source raises, with a two-observation resolution.</summary>
    private static readonly IReadOnlyDictionary<string, FindingTypeDefinition> Catalog =
        new Dictionary<string, FindingTypeDefinition>(FindingTypes.All, StringComparer.Ordinal)
        {
            ["TEST_ANOMALY"] = new()
            {
                Id = "TEST_ANOMALY",
                SourceId = FindingSourceIds.Anomaly,
                Identity = "domain and service",
                Evidence = "the day's records in the client's file",
                Resolution = "two normal windows in a row",
                SeverityRule = "warning above the score threshold",
                ResolveAfterAbsent = 2,
            },
        };

    public FindingLifecycleTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        Onboard("local", "acme.example", "r-1", "Acme Corp");
        _acme = IdsAsync("local", "acme-corp", "acme.example").GetAwaiter().GetResult();
        _lifecycle = new FindingLifecycle(_dbPath, _clock, Catalog);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    // ---- identity ------------------------------------------------------------------

    [Fact]
    public async Task TheSameConditionObservedTwiceIsOneFindingWithOneObservedEvent()
    {
        var first = await _lifecycle.ObserveAsync(Drift(_acme));
        Assert.Equal(ObserveOutcome.Created, first.Outcome);

        _clock.Advance(TimeSpan.FromDays(1));
        var second = await _lifecycle.ObserveAsync(Drift(_acme));

        Assert.Equal(ObserveOutcome.Unchanged, second.Outcome);
        Assert.Equal(first.Finding.Id, second.Finding.Id);
        Assert.Equal(2, second.Finding.ObservationCount);
        Assert.Equal(first.Finding.FirstObservedAt, second.Finding.FirstObservedAt);
        Assert.Equal(_clock.Now, second.Finding.LastObservedAt);
        Assert.Equal(0, second.Finding.AbsentCount);

        var events = await _lifecycle.Store.EventsAsync(first.Finding.Id);
        Assert.Equal(FindingEventKinds.Observed, Assert.Single(events).Kind);
        Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
    }

    [Fact]
    public async Task AChangedSeverityOrTypeOnReobservationIsRecordedOnTheSameFinding()
    {
        var changed = await _lifecycle.ObserveAsync(Drift(_acme, severity: "warning", type: FindingTypes.DmarcPolicyChanged, title: "DMARC: pct=100 → pct=50."));
        var weakened = await _lifecycle.ObserveAsync(Drift(_acme));

        Assert.Equal(ObserveOutcome.Changed, weakened.Outcome);
        Assert.Equal(changed.Finding.Id, weakened.Finding.Id);
        Assert.Equal("critical", weakened.Finding.Severity);
        Assert.Equal(FindingTypes.DmarcPolicyWeakened, weakened.Finding.Type);

        var kinds = (await _lifecycle.Store.EventsAsync(changed.Finding.Id)).Select(e => e.Kind).ToList();
        Assert.Equal([FindingEventKinds.Observed, FindingEventKinds.SeverityChanged, FindingEventKinds.TypeChanged], kinds);
        Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
    }

    /// <summary>
    /// The same finding, a different kind of wrong at the same type and
    /// severity: a loosened record that is then removed. Updating the row
    /// silently would leave the change feed, a destination and a ticket
    /// believing nothing had happened.
    /// </summary>
    [Fact]
    public async Task AChangedConditionAtTheSameTypeAndSeverityIsRecordedOnTheSameFinding()
    {
        var loosened = await _lifecycle.ObserveAsync(Drift(_acme));
        _clock.Advance(TimeSpan.FromDays(1));
        var removed = await _lifecycle.ObserveAsync(Drift(_acme, rule: "record_removed", title: "DMARC: the record was removed.", evidence: "drift:dr-2"));

        Assert.Equal(ObserveOutcome.Changed, removed.Outcome);
        Assert.Equal(loosened.Finding.Id, removed.Finding.Id);
        Assert.Equal("record_removed", removed.Finding.Rule);
        Assert.Equal("DMARC: the record was removed.", removed.Finding.Title);
        Assert.Equal("drift:dr-2", removed.Finding.EvidenceRef);

        var events = await _lifecycle.Store.EventsAsync(loosened.Finding.Id);
        Assert.Equal([FindingEventKinds.Observed, FindingEventKinds.ConditionChanged], events.Select(e => e.Kind).ToList());
        Assert.Equal("policy_loosened", events[1].FromValue);
        Assert.Equal("record_removed", events[1].ToValue);
        Assert.Equal("DMARC: the record was removed.", events[1].Note);

        // The same condition seen again, with the same evidence or none new, is still not a change.
        _clock.Advance(TimeSpan.FromDays(1));
        var again = await _lifecycle.ObserveAsync(Drift(_acme, rule: "record_removed", title: "DMARC: the record was removed.", evidence: "drift:dr-2"));
        Assert.Equal(ObserveOutcome.Unchanged, again.Outcome);
        Assert.Equal(2, (await _lifecycle.Store.EventsAsync(loosened.Finding.Id)).Count);

        // A new piece of evidence for the same sentence is a change; the old evidence carried along is not.
        var moved = await _lifecycle.ObserveAsync(Drift(_acme, rule: "record_removed", title: "DMARC: the record was removed.", evidence: "drift:dr-3"));
        Assert.Equal(ObserveOutcome.Changed, moved.Outcome);
        Assert.Equal(3, (await _lifecycle.Store.EventsAsync(loosened.Finding.Id)).Count);
    }

    // ---- resolution is evidence ------------------------------------------------------

    [Fact]
    public async Task AFailedObservationMarksFindingsUnknownAndResolvesNothing()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));

        var marked = await _lifecycle.MarkUnknownAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, _acme.DomainId, "the lookup timed out");

        Assert.Equal(1, marked);
        var unknown = (await _lifecycle.Store.GetAsync(observed.Finding.Id))!;
        Assert.Equal(SourceStates.Unknown, unknown.SourceState);
        Assert.Null(unknown.SourceResolvedAt);
        Assert.Equal(0, unknown.AbsentCount);
        Assert.True(unknown.InQueue, "a finding nothing can see is still open");
        Assert.Contains(await _lifecycle.Store.EventsAsync(unknown.Id),
            e => e.Kind == FindingEventKinds.SourceUnknown && e.Note!.Contains("timed out", StringComparison.Ordinal));

        // A second failure changes nothing more; the source seeing it again is not a new finding.
        Assert.Equal(0, await _lifecycle.MarkUnknownAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, _acme.DomainId));
        var back = await _lifecycle.ObserveAsync(Drift(_acme));
        Assert.Equal(ObserveOutcome.KnownAgain, back.Outcome);
        Assert.Equal(SourceStates.Active, back.Finding.SourceState);
        Assert.Equal(observed.Finding.Id, back.Finding.Id);
    }

    [Fact]
    public async Task ASuccessfulObservationWithoutTheConditionResolvesAfterTheTypesThreshold()
    {
        // DNS drift: one read that matches what was published before is enough.
        var drift = await _lifecycle.ObserveAsync(Drift(_acme));
        var result = await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, _acme.DomainId, new HashSet<string>(StringComparer.Ordinal));

        Assert.Equal(new FindingReconciliation(1, 1), result);
        var resolved = (await _lifecycle.Store.GetAsync(drift.Finding.Id))!;
        Assert.Equal(SourceStates.Resolved, resolved.SourceState);
        Assert.Equal(_clock.Now, resolved.SourceResolvedAt);
        Assert.False(resolved.InQueue);

        // Reporting stopped: reports have to keep arriving for three nightly observations.
        var quiet = await _lifecycle.ObserveAsync(ReportingStopped(_acme));
        for (var night = 1; night <= 2; night++)
        {
            _clock.Advance(TimeSpan.FromDays(1));
            await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Reports, null, new HashSet<string>(StringComparer.Ordinal));
            var still = (await _lifecycle.Store.GetAsync(quiet.Finding.Id))!;
            Assert.Equal(SourceStates.Active, still.SourceState);
            Assert.Equal(night, still.AbsentCount);
        }

        _clock.Advance(TimeSpan.FromDays(1));
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Reports, null, new HashSet<string>(StringComparer.Ordinal));
        var gone = (await _lifecycle.Store.GetAsync(quiet.Finding.Id))!;
        Assert.Equal(SourceStates.Resolved, gone.SourceState);
        Assert.Equal(
            [FindingEventKinds.Observed, FindingEventKinds.ObservationAbsent, FindingEventKinds.ObservationAbsent, FindingEventKinds.SourceResolved],
            (await _lifecycle.Store.EventsAsync(gone.Id)).Select(e => e.Kind).ToList());
    }

    [Fact]
    public async Task ASeenConditionInterruptsTheCountTowardsResolution()
    {
        var quiet = await _lifecycle.ObserveAsync(ReportingStopped(_acme));
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Reports, null, new HashSet<string>(StringComparer.Ordinal));
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Reports, null, new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(2, (await _lifecycle.Store.GetAsync(quiet.Finding.Id))!.AbsentCount);

        // Seen again: the count starts over, so two quiet nights and a noisy one do not add up to three.
        var seen = await _lifecycle.ObserveAsync(ReportingStopped(_acme));
        Assert.Equal(0, seen.Finding.AbsentCount);
        Assert.Equal(SourceStates.Active, seen.Finding.SourceState);
    }

    [Fact]
    public async Task AConditionThatComesBackReopensTheSameFinding()
    {
        var first = await _lifecycle.ObserveAsync(Drift(_acme));
        await _lifecycle.SetAnalystStateAsync(first.Finding.Id, AnalystStates.Closed, "alex", "fixed in the registrar");
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, _acme.DomainId, new HashSet<string>(StringComparer.Ordinal));

        _clock.Advance(TimeSpan.FromDays(3));
        var again = await _lifecycle.ObserveAsync(Drift(_acme));

        Assert.Equal(ObserveOutcome.Reopened, again.Outcome);
        Assert.Equal(first.Finding.Id, again.Finding.Id);
        Assert.Equal(SourceStates.Active, again.Finding.SourceState);
        Assert.Equal(AnalystStates.Unreviewed, again.Finding.AnalystState);
        Assert.Equal(1, again.Finding.ReopenedCount);
        Assert.Null(again.Finding.SourceResolvedAt);
        Assert.True(again.Finding.InQueue);
        Assert.Contains(await _lifecycle.Store.EventsAsync(again.Finding.Id), e => e.Kind == FindingEventKinds.Reopened && e.Note!.Contains("3 days", StringComparison.Ordinal));
        Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
    }

    // ---- what a person decides is not evidence -----------------------------------------

    [Fact]
    public async Task ClosingAsAnalystNeverResolvesTheSource()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));

        var closed = (await _lifecycle.SetAnalystStateAsync(observed.Finding.Id, AnalystStates.Closed, "alex"))!;

        Assert.Equal(AnalystStates.Closed, closed.AnalystState);
        Assert.Equal(SourceStates.Active, closed.SourceState);
        Assert.Null(closed.SourceResolvedAt);
        Assert.False(closed.InQueue);

        // The source still sees it: the same row, still closed, still active.
        var seen = await _lifecycle.ObserveAsync(Drift(_acme));
        Assert.Equal(ObserveOutcome.Unchanged, seen.Outcome);
        Assert.Equal(AnalystStates.Closed, seen.Finding.AnalystState);
        Assert.Equal(SourceStates.Active, seen.Finding.SourceState);

        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.SetAnalystStateAsync(observed.Finding.Id, "resolved", "alex"));
    }

    [Fact]
    public async Task AcknowledgingMovesUnreviewedToInvestigatingAndIsRecorded()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));

        var seen = (await _lifecycle.AcknowledgeAsync(observed.Finding.Id, "alex", "looking"))!;

        Assert.Equal(AnalystStates.Investigating, seen.AnalystState);
        Assert.True(seen.InQueue);
        Assert.Contains(await _lifecycle.Store.EventsAsync(seen.Id), e => e.Kind == FindingEventKinds.Acknowledged && e.Actor == "alex");
    }

    // ---- exceptions ------------------------------------------------------------------

    [Fact]
    public async Task AnExceptionHidesTheFindingFromTheQueueWhileObservationContinues()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));

        var excepted = (await _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30)))!;

        Assert.True(excepted.IsExcepted);
        Assert.False(excepted.InQueue);
        Assert.Equal(AnalystStates.AcceptedRisk, excepted.AnalystState);
        Assert.Equal("alex", excepted.OpenException!.Approver);
        Assert.Empty(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId, InQueueOnly = true }));
        Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId, ExceptedOnly = true }));

        _clock.Advance(TimeSpan.FromDays(1));
        var stillSeen = await _lifecycle.ObserveAsync(Drift(_acme));

        Assert.Equal(_clock.Now, stillSeen.Finding.LastObservedAt);
        Assert.Equal(2, stillSeen.Finding.ObservationCount);
        Assert.True(stillSeen.Finding.IsExcepted, "observation carries on; the exception does not blind the source");
        Assert.False(stillSeen.Finding.InQueue);
    }

    [Fact]
    public async Task AnExpiredExceptionResurfacesAFindingItsSourceStillSees()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));
        await _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30, expiresInDays: 2));

        _clock.Advance(TimeSpan.FromDays(3));
        await _lifecycle.ObserveAsync(Drift(_acme));
        var expired = await _lifecycle.ExpireExceptionsAsync();

        Assert.Equal(1, expired);
        var back = (await _lifecycle.Store.GetAsync(observed.Finding.Id))!;
        Assert.False(back.IsExcepted);
        Assert.True(back.InQueue);
        Assert.Equal(AnalystStates.Unreviewed, back.AnalystState);
        Assert.Contains(await _lifecycle.Store.EventsAsync(back.Id), e => e.Kind == FindingEventKinds.ExceptionExpired && e.Note!.Contains("back in the queue", StringComparison.Ordinal));
        Assert.Equal(0, await _lifecycle.ExpireExceptionsAsync());
    }

    [Fact]
    public async Task AnExceptionNeedsAReviewDateInTheFutureAnApproverAndACompensatingControl()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));

        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: -1)));
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30) with { CompensatingControl = " " }));
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30) with { Approver = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30) with { Reason = "" }));
        Assert.False((await _lifecycle.Store.GetAsync(observed.Finding.Id))!.IsExcepted);

        await _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 30));
        await Assert.ThrowsAsync<InvalidOperationException>(() => _lifecycle.ExceptAsync(observed.Finding.Id, Request(days: 60)));

        Assert.True(await _lifecycle.EndExceptionAsync(observed.Finding.Id, "alex", "vendor fixed it"));
        Assert.False(await _lifecycle.EndExceptionAsync(observed.Finding.Id, "alex"));
        var ended = (await _lifecycle.Store.GetAsync(observed.Finding.Id))!;
        Assert.False(ended.IsExcepted);
        Assert.True(ended.InQueue);
    }

    // ---- other engines, same lifecycle --------------------------------------------------

    [Fact]
    public async Task AnAnomalySourceGoesThroughTheSameLifecycle()
    {
        var observation = new Observation
        {
            TenantId = _acme.TenantId,
            ClientId = _acme.ClientId,
            DomainId = _acme.DomainId,
            SourceId = FindingSourceIds.Anomaly,
            Type = "TEST_ANOMALY",
            Severity = "warning",
            Title = "Volume 90% under the 28-day median; receivers 3 → 1.",
            DedupKey = "anomaly:" + _acme.DomainId + ":volume:mailchimp",
            EvidenceRef = "records:2026-09-28",
            PayloadJson = """{"score":0.91,"observationWindow":"2026-09-28","baselineWindow":"2026-08-31/2026-09-27","features":[{"name":"messages","deviation":-4.2},{"name":"receivers","deviation":-2.0}],"modelVersion":"mad-1"}""",
        };

        var raised = await _lifecycle.ObserveAsync(observation);
        Assert.Equal(ObserveOutcome.Created, raised.Outcome);
        Assert.Contains("\"modelVersion\":\"mad-1\"", raised.Finding.PayloadJson, StringComparison.Ordinal);
        Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId, InQueueOnly = true }));

        // Two normal windows in a row, as the type says; one is not enough.
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Anomaly, _acme.DomainId, new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(SourceStates.Active, (await _lifecycle.Store.GetAsync(raised.Finding.Id))!.SourceState);
        await _lifecycle.ReconcileAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.Anomaly, _acme.DomainId, new HashSet<string>(StringComparer.Ordinal));
        Assert.Equal(SourceStates.Resolved, (await _lifecycle.Store.GetAsync(raised.Finding.Id))!.SourceState);
    }

    [Fact]
    public async Task ATypeNoSourceDefinesIsRefused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ObserveAsync(Drift(_acme) with { Type = "UNKNOWN_SENDER" }));
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ObserveAsync(Drift(_acme) with { SourceId = FindingSourceIds.Reports }));
        await Assert.ThrowsAsync<ArgumentException>(() => _lifecycle.ObserveAsync(Drift(_acme) with { Severity = "high" }));
        Assert.Empty(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
    }

    // ---- isolation ---------------------------------------------------------------------

    [Fact]
    public async Task OneOrganizationCannotSeeOrTouchAnothersFindings()
    {
        await new OrganizationStore(_dbPath).CreateAsync("Other MSP", slug: "other");
        Onboard("other", "globex.example", "r-2", "Globex");
        var globex = await IdsAsync("other", "globex", "globex.example");

        var ours = await _lifecycle.ObserveAsync(Drift(_acme));
        var theirs = await _lifecycle.ObserveAsync(Drift(globex));

        Assert.Equal(ours.Finding.Id, Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId })).Id);
        Assert.Equal(theirs.Finding.Id, Assert.Single(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = globex.TenantId })).Id);
        Assert.Equal(2, (await _lifecycle.Store.ListAsync(new FindingFilter())).Count);

        Assert.Null(await _lifecycle.Store.GetAsync(theirs.Finding.Id, _acme.TenantId));
        Assert.Null(await _lifecycle.AcknowledgeAsync(theirs.Finding.Id, "alex", tenantId: _acme.TenantId));
        Assert.Null(await _lifecycle.SetAnalystStateAsync(theirs.Finding.Id, AnalystStates.Closed, "alex", tenantId: _acme.TenantId));
        Assert.Null(await _lifecycle.ExceptAsync(theirs.Finding.Id, Request(days: 30), tenantId: _acme.TenantId));
        Assert.Equal(AnalystStates.Unreviewed, (await _lifecycle.Store.GetAsync(theirs.Finding.Id))!.AnalystState);

        // A customer login sees its own client's and nothing else's.
        Assert.Empty(await _lifecycle.Store.ListAsync(new FindingFilter { TenantId = _acme.TenantId, ClientSlug = "globex" }));
        Assert.Null(await _lifecycle.Store.GetAsync(ours.Finding.Id, _acme.TenantId, "globex"));
    }

    // ---- the contract ------------------------------------------------------------------

    [Fact]
    public async Task TheContractCarriesAPointerAtTheEvidenceAndNeverTheEvidence()
    {
        var observed = await _lifecycle.ObserveAsync(Drift(_acme));
        var change = Assert.Single(await _lifecycle.Store.EventsAsync(observed.Finding.Id));

        var contract = FindingContract.For(observed.Finding, change, "local", "https://dmarc.msp.example/");
        var json = contract.ToJson();

        Assert.Contains("\"schema\":\"dmarc-monitor.finding.v1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"payloadVersion\":\"finding.v1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"evidenceUri\":\"https://dmarc.msp.example/domains/acme.example\"", json, StringComparison.Ordinal);
        Assert.Contains("\"evidenceRef\":\"drift:dr-1\"", json, StringComparison.Ordinal);
        Assert.Contains("\"dedupKey\":\"dns:" + _acme.DomainId + ":dmarc\"", json, StringComparison.Ordinal);
        Assert.Contains("\"eventKind\":\"Observed\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("oldValue", json, StringComparison.Ordinal);
        Assert.DoesNotContain("newValue", json, StringComparison.Ordinal);
        Assert.DoesNotContain("v=DMARC1", json, StringComparison.Ordinal);

        var back = FindingContract.FromJson(json)!;
        Assert.Equal(contract.FindingId, back.FindingId);
        Assert.Equal(contract.Client, back.Client);
        Assert.Equal(contract.ObservedAt, back.ObservedAt);
        Assert.Equal(SourceStates.Active, back.SourceState);
        Assert.Equal(AnalystStates.Unreviewed, back.AnalystState);
        Assert.Null(back.ControlId);
    }

    // ---- source health -----------------------------------------------------------------

    [Fact]
    public async Task SourceHealthNeverShowsSilenceAsHealthy()
    {
        var registry = new FindingSourceRegistry(_dbPath, _clock);
        Assert.Empty(await registry.ListAsync(_acme.TenantId));

        var never = new FindingSource { Id = "x", TenantId = _acme.TenantId, Kind = FindingSourceIds.DnsScan, ExpectedEveryHours = 24 };
        Assert.Equal(SourceHealth.Unknown, never.HealthAt(_clock.Now));

        await registry.RecordAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, succeeded: true, error: null, expectedEveryHours: 24);
        Assert.Equal(SourceHealth.Healthy, (await HealthAsync(registry)).Health);

        _clock.Advance(TimeSpan.FromDays(2));
        Assert.Equal(SourceHealth.Stale, (await HealthAsync(registry)).Health);

        await registry.RecordAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, succeeded: false, error: "the lookup timed out", expectedEveryHours: 24);
        var failed = await HealthAsync(registry);
        Assert.Equal(SourceHealth.Failed, failed.Health);
        Assert.Equal("the lookup timed out", failed.Source.LastError);

        await registry.RecordAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, succeeded: true, error: null, expectedEveryHours: 24);
        var healthy = await HealthAsync(registry);
        Assert.Equal(SourceHealth.Healthy, healthy.Health);
        Assert.Null(healthy.Source.LastError);

        _clock.Advance(TimeSpan.FromHours(1));
        await registry.RecordAsync(_acme.TenantId, _acme.ClientId, FindingSourceIds.DnsScan, succeeded: false, error: "SERVFAIL", expectedEveryHours: 24);
        Assert.Equal(SourceHealth.Degraded, (await HealthAsync(registry)).Health);

        var row = Assert.Single(await registry.ListAsync(_acme.TenantId));
        Assert.Equal("acme-corp", row.ClientSlug);
        Assert.Equal(FindingSourceRegistry.IdFor(FindingSourceIds.DnsScan, _acme.TenantId, _acme.ClientId), row.Id);

        async Task<(FindingSource Source, string Health)> HealthAsync(FindingSourceRegistry r) => Assert.Single(await r.HealthAsync(_acme.TenantId));
    }

    // ---- fixture -------------------------------------------------------------------------

    private sealed record Ids(string TenantId, string ClientId, string DomainId);

    private static Observation Drift(
        Ids ids, string severity = "critical", string type = FindingTypes.DmarcPolicyWeakened,
        string title = "DMARC: p=quarantine → p=none.", string rule = "policy_loosened", string evidence = "drift:dr-1") => new()
    {
        TenantId = ids.TenantId,
        ClientId = ids.ClientId,
        DomainId = ids.DomainId,
        SourceId = FindingSourceIds.DnsScan,
        Type = type,
        Rule = rule,
        Severity = severity,
        Title = title,
        DedupKey = "dns:" + ids.DomainId + ":dmarc",
        EvidenceRef = evidence,
        ExpectedRef = "snapshot:before",
    };

    private static Observation ReportingStopped(Ids ids) => new()
    {
        TenantId = ids.TenantId,
        ClientId = ids.ClientId,
        DomainId = ids.DomainId,
        SourceId = FindingSourceIds.Reports,
        Type = FindingTypes.ReportingStopped,
        Severity = "warning",
        Title = "No aggregate report has covered this domain for 9 days.",
        DedupKey = "reporting:" + ids.DomainId,
        EvidenceRef = "report:r-1",
    };

    private ExceptionRequest Request(int days, int? expiresInDays = null) => new()
    {
        Reason = "Migration to a new mail platform in progress.",
        Approver = "alex",
        CompensatingControl = "Vendor include re-added by Friday; monitored daily.",
        ReviewAt = _clock.Now.AddDays(days),
        ExpiresAt = expiresInDays is { } e ? _clock.Now.AddDays(e) : null,
        By = "sam",
    };

    /// <summary>A report files the domain; a client is made and the domain filed under it.</summary>
    private void Onboard(string organization, string domain, string reportId, string clientName)
    {
        var xml = SyntheticReports.AggregateXml(reportId, domain);
        var store = new ReportStore(_dbPath, organization);
        store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, $"msg-{reportId}").GetAwaiter().GetResult();
        var slug = store.CreateClientAsync(clientName).GetAwaiter().GetResult()!;
        store.AssignDomainAsync(domain, slug).GetAwaiter().GetResult();
    }

    private async Task<Ids> IdsAsync(string organization, string clientSlug, string domain)
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath};Pooling=False");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT t.id, c.id, d.id
            FROM tenants t
            JOIN clients c ON c.tenant_id = t.id AND c.slug = $client
            JOIN domains d ON d.client_id = c.id AND d.name = $domain
            WHERE t.slug = $org
            """;
        command.Parameters.AddWithValue("$org", organization);
        command.Parameters.AddWithValue("$client", clientSlug);
        command.Parameters.AddWithValue("$domain", domain);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"no {clientSlug}/{domain} in {organization}");
        return new Ids(reader.GetString(0), reader.GetString(1), reader.GetString(2));
    }

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; private set; } = new(2026, 9, 29, 3, 20, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public void Advance(TimeSpan by) => Now += by;
    }
}
