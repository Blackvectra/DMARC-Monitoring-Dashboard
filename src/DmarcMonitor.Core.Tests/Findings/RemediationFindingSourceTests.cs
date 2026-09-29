using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Findings;

/// <summary>
/// A change this product applies is a finding until it is known to have
/// taken: accepted by the provider is not served by DNS, and served is not
/// in force at the receivers. Applying resolves nothing; a read serving the
/// value moves the finding on and resolves the drift it answered on the
/// same read; a receiver's report showing the policy, or fourteen days
/// without one, is the end; a rollback withdraws it and puts the drift's
/// expectation back.
/// </summary>
public sealed class RemediationFindingSourceTests : IDisposable
{
    private const string Domain = "acme.example";
    private const string Name = "_dmarc.acme.example";
    private const string Original = "v=DMARC1; p=quarantine; rua=mailto:d@msp.example";
    private const string Loosened = "v=DMARC1; p=none; rua=mailto:d@msp.example";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-fixfindings-{Guid.NewGuid():N}.db");
    private readonly RemediationService _service;
    private readonly RemediationFindingSource _source;
    private readonly DnsSnapshotStore _dns;
    private readonly FindingStore _findings;
    private readonly InMemoryDnsProvider _zone = new();
    private readonly Ids _acme;

    public RemediationFindingSourceTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        Onboard("local", Domain, "r-1", "Acme Corp");
        _service = new RemediationService(_dbPath);
        _source = new RemediationFindingSource(_dbPath);
        _dns = new DnsSnapshotStore(_dbPath);
        _findings = new FindingStore(_dbPath);
        _acme = IdsAsync("local", "acme-corp", Domain).GetAwaiter().GetResult();
        _zone.Add(Name, "TXT", Loosened);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    [Fact]
    public async Task ApplyingAChangeRaisesAFindingThatWaitsForDnsAndTellsTheDriftWhatToExpect()
    {
        var drift = await DriftAsync();
        var (plan, changeId) = await ApplyAsync();

        var pending = await RemediationAsync();
        Assert.Equal(FindingTypes.RemediationPendingVerification, pending.Type);
        Assert.Equal(ChangeType.DmarcPolicy, pending.Rule);
        Assert.Equal("info", pending.Severity);
        Assert.Equal(RemediationFindingSource.DedupKey(changeId), pending.DedupKey);
        Assert.Equal("change:" + changeId, pending.EvidenceRef);
        Assert.Equal(DnsFindingSource.RecordRef(plan.ProposedValue), pending.ExpectedRef);
        Assert.Equal(drift.Id, pending.RelatedFindingId);
        Assert.StartsWith("Applied: Move acme.example from p=none to p=quarantine at pct=50.", pending.Title, StringComparison.Ordinal);
        Assert.Contains("Awaiting DNS verification", pending.Title, StringComparison.Ordinal);

        // Applied is not verified: nothing is resolved by the write.
        Assert.Equal(SourceStates.Active, pending.SourceState);
        Assert.Equal(RemediationStages.DnsPending, pending.RemediationStage);
        Assert.True(pending.AwaitsVerification);
        Assert.Contains(await _findings.EventsAsync(pending.Id), e => e.Kind == FindingEventKinds.RemediationStaged && e.ToValue == RemediationStages.DnsPending);

        // The drift it answers now expects what was applied, and says why.
        var told = (await _findings.GetAsync(drift.Id))!;
        Assert.Equal(SourceStates.Active, told.SourceState);
        Assert.Equal(DnsFindingSource.RecordRef(plan.ProposedValue), told.ExpectedRef);
        var moved = Assert.Single(await _findings.EventsAsync(drift.Id), e => e.Kind == FindingEventKinds.ExpectedChanged);
        Assert.Equal(DnsFindingSource.RecordRef(Original), moved.FromValue);
        Assert.Contains(changeId, moved.Note, StringComparison.Ordinal);

        // The value written stays in the client's file; the organization's database holds hashes.
        Assert.DoesNotContain("rua=mailto:d@msp.example", OrganizationFileText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnsweringDriftWithTheRecordAsItWasMovesNoGoalposts()
    {
        var drift = await DriftAsync();
        var (plan, _) = await ApplyAsync(percent: 100);
        Assert.Equal(Original, plan.ProposedValue);

        // The drift already expected exactly this, so there is nothing to record.
        var same = (await _findings.GetAsync(drift.Id))!;
        Assert.Equal(DnsFindingSource.RecordRef(Original), same.ExpectedRef);
        Assert.DoesNotContain(await _findings.EventsAsync(drift.Id), e => e.Kind == FindingEventKinds.ExpectedChanged);
        Assert.Equal(drift.Id, (await RemediationAsync()).RelatedFindingId);

        await _dns.SaveAsync(Domain, Reading(Original));
        Assert.Equal(SourceStates.Resolved, (await _findings.GetAsync(drift.Id))!.SourceState);
        Assert.Equal(RemediationStages.EffectivenessPending, (await RemediationAsync()).RemediationStage);
    }

    [Fact]
    public async Task TheReadThatServesTheAppliedValueVerifiesTheChangeAndResolvesTheDriftTogether()
    {
        var drift = await DriftAsync();
        var (plan, _) = await ApplyAsync();

        await _dns.SaveAsync(Domain, Reading(plan.ProposedValue));

        var verified = await RemediationAsync();
        Assert.Equal(SourceStates.Active, verified.SourceState);
        Assert.Equal(RemediationStages.EffectivenessPending, verified.RemediationStage);
        Assert.Contains("DNS verified; awaiting a receiver's report", verified.Title, StringComparison.Ordinal);
        var stages = (await _findings.EventsAsync(verified.Id)).Where(e => e.Kind == FindingEventKinds.RemediationStaged).Select(e => e.ToValue).ToList();
        Assert.Equal([RemediationStages.DnsPending, RemediationStages.DnsVerified, RemediationStages.EffectivenessPending], stages);

        Assert.Equal(SourceStates.Resolved, (await _findings.GetAsync(drift.Id))!.SourceState);

        // The value arriving is the change, not new drift: two findings, and
        // the drift history marks the change as one this product expected.
        Assert.Equal(2, (await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId })).Count);
        var arrived = Assert.Single(await new DnsDriftStore(_dbPath).ListAsync(_acme.TenantId), d => d.NewValue == plan.ProposedValue);
        Assert.True(arrived.WasExpected);
    }

    [Fact]
    public async Task AChangeWithNoDriftToAnswerIsStillAFindingAndItsArrivalIsNotDrift()
    {
        await _dns.SaveAsync(Domain, Reading(Loosened));
        var (plan, _) = await ApplyAsync();

        var pending = await RemediationAsync();
        Assert.Null(pending.RelatedFindingId);

        await _dns.SaveAsync(Domain, Reading(plan.ProposedValue));

        var only = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(pending.Id, only.Id);
        Assert.Equal(RemediationStages.EffectivenessPending, only.RemediationStage);
    }

    [Fact]
    public async Task AReceiversReportShowingTheAppliedPolicyIsTheEvidenceTheChangeIsInForce()
    {
        await DriftAsync();
        var (plan, _) = await ApplyAsync();
        await _dns.SaveAsync(Domain, Reading(plan.ProposedValue));
        var applied = DateTimeOffset.UtcNow;

        // The report that filed the domain is from before the change; it shows nothing about it.
        Assert.Equal(0, await _source.CheckEffectivenessAsync());

        // A period after the change, but the receiver still applied the old policy.
        Report("r-2", "none", 100, applied.AddDays(1));
        Assert.Equal(0, await _source.CheckEffectivenessAsync());

        // The policy, but not at the percentage that was applied: not this change in force.
        Report("r-3", "quarantine", 100, applied.AddDays(2));
        Assert.Equal(0, await _source.CheckEffectivenessAsync());
        Assert.Equal(RemediationStages.EffectivenessPending, (await RemediationAsync()).RemediationStage);

        Report("r-4", "quarantine", 50, applied.AddDays(3));
        Assert.Equal(1, await _source.CheckEffectivenessAsync());

        var verified = await RemediationAsync();
        Assert.Equal(SourceStates.Resolved, verified.SourceState);
        Assert.False(verified.InQueue);
        var resolved = Assert.Single(await _findings.EventsAsync(verified.Id), e => e.Kind == FindingEventKinds.SourceResolved);
        Assert.Contains("receiver.example", resolved.Note, StringComparison.Ordinal);
        Assert.Contains("p=quarantine", resolved.Note, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.25", resolved.Note, StringComparison.Ordinal);

        // Nothing is resolved twice.
        Assert.Equal(0, await _source.CheckEffectivenessAsync());
    }

    [Fact]
    public async Task FourteenDaysAfterDnsVerificationWithNoReportItIsVerifiedByDnsOnlyAndSaysSo()
    {
        await DriftAsync();
        var (plan, _) = await ApplyAsync();
        await _dns.SaveAsync(Domain, Reading(plan.ProposedValue));
        var verifiedAt = DateTimeOffset.UtcNow;

        Assert.Equal(0, await _source.CheckEffectivenessAsync(now: verifiedAt.AddDays(13)));
        Assert.Equal(RemediationStages.EffectivenessPending, (await RemediationAsync()).RemediationStage);

        Assert.Equal(1, await _source.CheckEffectivenessAsync(now: verifiedAt.AddDays(15)));
        var finding = await RemediationAsync();
        Assert.Equal(SourceStates.Resolved, finding.SourceState);
        var resolved = Assert.Single(await _findings.EventsAsync(finding.Id), e => e.Kind == FindingEventKinds.SourceResolved);
        Assert.StartsWith("Verified by DNS only", resolved.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RollingBackWithdrawsTheFindingAndTheDriftExpectsWhatItDidBefore()
    {
        var drift = await DriftAsync();
        var (_, changeId) = await ApplyAsync();

        var outcome = await _service.RollBackAsync(changeId, _zone, "tester", "wrong domain");
        Assert.True(outcome.Applied);

        var withdrawn = await RemediationAsync();
        Assert.Equal(SourceStates.Resolved, withdrawn.SourceState);
        Assert.Equal(RemediationStages.DnsPending, withdrawn.RemediationStage);
        var resolved = Assert.Single(await _findings.EventsAsync(withdrawn.Id), e => e.Kind == FindingEventKinds.SourceResolved);
        Assert.Contains("Rolled back by tester: wrong domain", resolved.Note, StringComparison.Ordinal);
        Assert.Contains("withdrawn, not verified", resolved.Note, StringComparison.Ordinal);

        var restored = (await _findings.GetAsync(drift.Id))!;
        Assert.Equal(SourceStates.Active, restored.SourceState);
        Assert.Equal(DnsFindingSource.RecordRef(Original), restored.ExpectedRef);
        Assert.Equal(2, (await _findings.EventsAsync(drift.Id)).Count(e => e.Kind == FindingEventKinds.ExpectedChanged));

        // Only the record as it was before the drift resolves it now.
        await _dns.SaveAsync(Domain, Reading(Original));
        Assert.Equal(SourceStates.Resolved, (await _findings.GetAsync(drift.Id))!.SourceState);
    }

    [Fact]
    public async Task ADayOnWithDnsNotServingItTheFindingIsAWarningUntilItDoes()
    {
        var (plan, _) = await ApplyAsync();
        var now = DateTimeOffset.UtcNow;
        var stillOld = new Dictionary<string, string>(StringComparer.Ordinal) { ["dmarc"] = Loosened };

        Assert.Equal(1, await _source.ObserveDomainAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, stillOld, now.AddHours(2)));
        var soon = await RemediationAsync();
        Assert.Equal("info", soon.Severity);
        Assert.Equal(2, soon.ObservationCount);

        Assert.Equal(1, await _source.ObserveDomainAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, stillOld, now.AddDays(2)));
        var slow = await RemediationAsync();
        Assert.Equal("warning", slow.Severity);
        Assert.Equal(RemediationStages.DnsPending, slow.RemediationStage);
        Assert.Contains("a day on", slow.Title, StringComparison.Ordinal);
        Assert.Contains(await _findings.EventsAsync(slow.Id), e => e.Kind == FindingEventKinds.SeverityChanged);

        var served = new Dictionary<string, string>(StringComparer.Ordinal) { ["dmarc"] = plan.ProposedValue };
        Assert.Equal(1, await _source.ObserveDomainAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, served, now.AddDays(3)));
        Assert.Equal(RemediationStages.EffectivenessPending, (await RemediationAsync()).RemediationStage);

        // Nothing left waiting on DNS for this domain.
        Assert.Equal(0, await _source.ObserveDomainAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, served, now.AddDays(4)));
    }

    [Fact]
    public async Task TheVerifyPollMovesTheFindingOnOnceAndNotForAChangeItDoesNotKnow()
    {
        var (_, changeId) = await ApplyAsync();

        Assert.True(await _source.DnsVerifiedAsync(changeId));
        Assert.Equal(RemediationStages.EffectivenessPending, (await RemediationAsync()).RemediationStage);

        Assert.False(await _source.DnsVerifiedAsync(changeId));
        Assert.False(await _source.DnsVerifiedAsync("no-such-change"));
        Assert.False(await _source.RolledBackAsync("no-such-change", "tester", "because"));
    }

    [Fact]
    public async Task AChangeWithNoReportEvidenceToWaitForResolvesWhenDnsServesIt()
    {
        var plan = TransportPlanner.TlsReporting(Domain, null, "tls@msp.example");
        var raised = await _source.AppliedAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, "change-tls-1", plan, "tester");
        Assert.Equal(RemediationStages.DnsPending, raised.RemediationStage);
        Assert.Equal(ChangeType.TlsRpt, raised.Rule);
        Assert.Null(raised.RelatedFindingId);

        var served = new Dictionary<string, string>(StringComparer.Ordinal) { ["tls-rpt"] = plan.ProposedValue };
        await _source.ObserveDomainAsync(_acme.TenantId, _acme.ClientId, _acme.DomainId, served, DateTimeOffset.UtcNow);

        var done = (await _findings.GetAsync(raised.Id))!;
        Assert.Equal(SourceStates.Resolved, done.SourceState);
        Assert.Equal(RemediationStages.DnsVerified, done.RemediationStage);
        var resolved = Assert.Single(await _findings.EventsAsync(done.Id), e => e.Kind == FindingEventKinds.SourceResolved);
        Assert.Contains("no runtime evidence applies", resolved.Note, StringComparison.Ordinal);
    }

    // ---- fixture -------------------------------------------------------------------------

    private sealed record Ids(string TenantId, string ClientId, string DomainId);

    /// <summary>The record loosened from quarantine to none, as the nightly scan would see it: a drift finding.</summary>
    private async Task<Finding> DriftAsync()
    {
        await _dns.SaveAsync(Domain, Reading(Original));
        await _dns.SaveAsync(Domain, Reading(Loosened));
        var drift = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(FindingTypes.DmarcPolicyWeakened, drift.Type);
        return drift;
    }

    /// <summary>
    /// The policy put back to quarantine from the Fix page, in the in-memory
    /// zone: at pct=50 by default, a staged answer whose record text is not
    /// what the domain served before the drift.
    /// </summary>
    private async Task<(ChangePlan Plan, string ChangeId)> ApplyAsync(int percent = 50)
    {
        var plan = DmarcPolicyPlanner.Advance(Domain, Loosened, "quarantine", percent);
        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "because");
        Assert.True(outcome.Applied, outcome.Message);
        Assert.Equal("", outcome.Error);
        Assert.Equal([plan.ProposedValue], _zone.ValuesAt(Name));
        return (plan, outcome.ChangeId!);
    }

    private async Task<Finding> RemediationAsync() =>
        Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId, Types = [FindingTypes.RemediationPendingVerification] }));

    private static PublishedRecords Reading(string? dmarc) => new()
    {
        Domain = Domain,
        SpfRecords = ["v=spf1 include:_spf.mail.example -all"],
        DmarcRecord = dmarc,
        SpfLookups = 2,
    };

    /// <summary>A receiver's report of the domain for one day from <paramref name="begin"/>, with the policy it says it applied.</summary>
    private void Report(string reportId, string policy, int pct, DateTimeOffset begin)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>receiver.example</org_name>
                <email>noreply@receiver.example</email>
                <report_id>{reportId}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddDays(1).ToUnixTimeSeconds() - 1}</end></date_range>
              </report_metadata>
              <policy_published><domain>{Domain}</domain><p>{policy}</p><pct>{pct}</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{Domain}</header_from></identifiers>
                <auth_results><dkim><domain>{Domain}</domain><result>pass</result></dkim><spf><domain>{Domain}</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;
        new ReportStore(_dbPath, "local").SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, "msg-" + reportId).GetAwaiter().GetResult();
    }

    private string OrganizationFileText() => FileText(_dbPath) + FileText(_dbPath + "-wal");

    private static string FileText(string path) => File.Exists(path) ? File.ReadAllText(path) : "";

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
}
