using System.Globalization;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Findings;

/// <summary>
/// Reports that stop arriving, as a finding: only for a domain that reported
/// regularly, only while the collector is known to have been listening, and
/// never for an organization whose mailbox as a whole has gone quiet. A
/// report covering the domain again resolves it after three observations,
/// and the same finding reopens when it goes quiet once more.
/// </summary>
public sealed class ReportsFindingSourceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 3, 30, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset LastWeekly = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);

    private const string Regular = "regular.example";
    private const string Sporadic = "sporadic.example";
    private const string Fresh = "fresh.example";
    private const string Beta = "beta.example";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-reportfindings-{Guid.NewGuid():N}.db");
    private readonly TestClock _clock = new(Now);
    private readonly ReportsFindingSource _source;
    private readonly FindingStore _findings;
    private readonly FindingSourceRegistry _registry;
    private readonly ClientDatabases _files;
    private readonly Ids _regular;
    private readonly Ids _beta;

    public ReportsFindingSourceTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        _files = new ClientDatabases(_dbPath);
        _source = new ReportsFindingSource(_dbPath, _clock);
        _findings = new FindingStore(_dbPath);
        _registry = new FindingSourceRegistry(_dbPath, _clock);

        // Acme: one domain a receiver reported on every week until the 12th,
        // one it mentions now and then, and one reported on yesterday.
        Onboard("local", "Acme Corp", Regular, Sporadic, Fresh);
        foreach (var weeks in Enumerable.Range(0, 5)) { Report("local", Regular, $"reg-{weeks}", LastWeekly.AddDays(-7 * weeks)); }
        Report("local", Sporadic, "spo-1", new DateTimeOffset(2026, 9, 10, 0, 0, 0, TimeSpan.Zero));
        Report("local", Sporadic, "spo-2", new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero));
        Report("local", Fresh, "fresh-1", Now.AddDays(-1));

        // Another organization's customer, reported on weekly until the 12th too.
        Onboard("other-msp", "Beta Ltd", Beta);
        foreach (var weeks in Enumerable.Range(0, 5)) { Report("other-msp", Beta, $"beta-{weeks}", LastWeekly.AddDays(-7 * weeks)); }

        _regular = IdsAsync("local", "acme-corp", Regular).GetAwaiter().GetResult();
        _beta = IdsAsync("other-msp", "beta-ltd", Beta).GetAwaiter().GetResult();
        StampIngestedAsync(_regular.ClientId, Now.AddHours(-2)).GetAwaiter().GetResult();
        StampIngestedAsync(_beta.ClientId, Now.AddHours(-2)).GetAwaiter().GetResult();
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    [Fact]
    public async Task ADomainThatReportedWeeklyThenWentQuietIsAFindingNamingItsNewestReport()
    {
        await CollectedAsync("local");

        var observed = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.Null(observed.NotObserved);
        Assert.Equal(1, observed.Quiet);
        Assert.Equal(0, observed.Reporting);

        // The parked domain and the one reported on yesterday raise nothing.
        var finding = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
        Assert.Equal(FindingTypes.ReportingStopped, finding.Type);
        Assert.Equal("quiet", finding.Rule);
        Assert.Equal("warning", finding.Severity);
        Assert.Equal(Regular, finding.Domain);
        Assert.Equal(ReportsFindingSource.DedupKey(_regular.DomainId), finding.DedupKey);
        Assert.Equal("report:" + await NewestReportIdAsync(_regular.ClientId, _regular.DomainId), finding.EvidenceRef);
        Assert.Equal("regular.example: no report has covered it since 2026-09-12, after reports in 5 of the 5 weeks before.", finding.Title);
        Assert.Equal(SourceStates.Active, finding.SourceState);
        Assert.True(finding.InQueue);

        // Another night of silence is the same finding, seen again, and not a change.
        _clock.Now = Now.AddDays(1);
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var again = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
        Assert.Equal(finding.Id, again.Id);
        Assert.Equal(2, again.ObservationCount);
        Assert.Equal(finding.Title, again.Title);
        Assert.Equal(FindingEventKinds.Observed, Assert.Single(await _findings.EventsAsync(again.Id)).Kind);
    }

    [Fact]
    public async Task SilenceSaysNothingUntilTheCollectorHasBeenHeardFrom()
    {
        // Never recorded: nothing is known about what did not arrive.
        var never = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.Contains("no collection has been recorded", never.NotObserved, StringComparison.Ordinal);
        Assert.Empty(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        // An organization no report has ever been stored for has nothing to record against.
        Assert.False(await _registry.RecordForOrganizationAsync("nobody", FindingSourceIds.Reports, true, null, 1));

        // The last run failed.
        Assert.True(await _registry.RecordForOrganizationAsync("local", FindingSourceIds.Reports, false, "the certificate has expired", 1, Now.AddHours(-1)));
        var failed = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.Equal("the last collection failed: the certificate has expired", failed.NotObserved);
        Assert.Empty(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        // It last succeeded too long ago for tonight's silence to mean anything.
        await CollectedAsync("local", Now.AddHours(-40));
        var stale = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.StartsWith("no collection has succeeded in the last 36 hours", stale.NotObserved, StringComparison.Ordinal);
        Assert.Empty(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        await CollectedAsync("local");
        Assert.Null((await _source.ObserveOrganizationAsync(_regular.TenantId)).NotObserved);
        Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
    }

    [Fact]
    public async Task ACollectorFailureMakesOpenFindingsUnknownAndResolvesNothing()
    {
        await CollectedAsync("local");
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var raised = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        _clock.Now = Now.AddDays(1);
        await _registry.RecordAsync(_regular.TenantId, null, FindingSourceIds.Reports, false, "mailbox not found", 1);
        var observed = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.Equal(1, observed.Unknown);
        Assert.Contains("mailbox not found", observed.NotObserved, StringComparison.Ordinal);

        var unknown = (await _findings.GetAsync(raised.Id))!;
        Assert.Equal(SourceStates.Unknown, unknown.SourceState);
        Assert.Null(unknown.SourceResolvedAt);
        Assert.Equal(0, unknown.AbsentCount);
        Assert.Contains(await _findings.EventsAsync(raised.Id), e => e.Kind == FindingEventKinds.SourceUnknown && e.Note!.Contains("mailbox not found", StringComparison.Ordinal));

        // A second failed night marks nothing twice; a good one, with the
        // other domains' reports arriving again, sees it again.
        _clock.Now = Now.AddDays(2);
        Assert.Equal(0, (await _source.ObserveOrganizationAsync(_regular.TenantId)).Unknown);
        await CollectedAsync("local", _clock.Now);
        await StampIngestedAsync(_regular.ClientId, _clock.Now.AddHours(-1));
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var back = (await _findings.GetAsync(raised.Id))!;
        Assert.Equal(SourceStates.Active, back.SourceState);
        Assert.Equal(2, back.ObservationCount);
    }

    [Fact]
    public async Task AnOrganizationWithNothingStoredInTheWindowIsTheCollectionNotADomain()
    {
        await CollectedAsync("local");
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var raised = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        // The collector runs and finds nothing, for everybody: the mailbox, not the domains.
        _clock.Now = Now.AddDays(3);
        await CollectedAsync("local", _clock.Now);
        var observed = await _source.ObserveOrganizationAsync(_regular.TenantId);
        Assert.Contains("nothing has been stored for any of the organization's domains", observed.NotObserved, StringComparison.Ordinal);
        Assert.Equal(1, observed.Unknown);
        Assert.Equal(SourceStates.Unknown, (await _findings.GetAsync(raised.Id))!.SourceState);
        Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
    }

    [Fact]
    public async Task ReportsArrivingAgainResolveTheFindingOnTheThirdObservationAndSilenceReopensIt()
    {
        await CollectedAsync("local");
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var raised = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));

        var resumed = new DateTimeOffset(2026, 9, 28, 0, 0, 0, TimeSpan.Zero);
        Report("local", Regular, "reg-back", resumed);
        await StampIngestedAsync(_regular.ClientId, Now.AddHours(-1));

        foreach (var night in Enumerable.Range(0, 2))
        {
            _clock.Now = Now.AddDays(night);
            await CollectedAsync("local", _clock.Now);
            await StampIngestedAsync(_regular.ClientId, _clock.Now.AddHours(-1));
            var observed = await _source.ObserveOrganizationAsync(_regular.TenantId);
            Assert.Equal(1, observed.Reporting);
            var counting = (await _findings.GetAsync(raised.Id))!;
            Assert.Equal(SourceStates.Active, counting.SourceState);
            Assert.Equal(night + 1, counting.AbsentCount);
        }

        _clock.Now = Now.AddDays(2);
        await CollectedAsync("local", _clock.Now);
        await StampIngestedAsync(_regular.ClientId, _clock.Now.AddHours(-1));
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var resolved = (await _findings.GetAsync(raised.Id))!;
        Assert.Equal(SourceStates.Resolved, resolved.SourceState);
        Assert.False(resolved.InQueue);

        // Quiet again nine days after the report that resumed, having been
        // regular in the five weeks before it: the same finding, reopened.
        _clock.Now = resumed.AddDays(9);
        await CollectedAsync("local", _clock.Now);
        await StampIngestedAsync(_regular.ClientId, _clock.Now.AddHours(-1));
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var reopened = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
        Assert.Equal(raised.Id, reopened.Id);
        Assert.Equal(SourceStates.Active, reopened.SourceState);
        Assert.Equal(1, reopened.ReopenedCount);
        Assert.Contains("since 2026-09-28, after reports in 4 of the 5 weeks before", reopened.Title, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ItIsCriticalWhenTheDmarcRecordNoLongerAsksForReports()
    {
        await CollectedAsync("local");
        var dns = new DnsSnapshotStore(_dbPath);

        await dns.SaveAsync(Regular, new PublishedRecords { Domain = Regular, SpfRecords = ["v=spf1 -all"], DmarcRecord = "v=DMARC1; p=none" });
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var critical = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
        Assert.Equal("critical", critical.Severity);
        Assert.Equal("rua_gone", critical.Rule);
        Assert.EndsWith(", and its DMARC record no longer asks for any.", critical.Title, StringComparison.Ordinal);

        // The address back in the record: still quiet, but no longer the record's doing.
        await dns.SaveAsync(Regular, new PublishedRecords { Domain = Regular, SpfRecords = ["v=spf1 -all"], DmarcRecord = "v=DMARC1; p=none; rua=mailto:d@msp.example" });
        _clock.Now = Now.AddDays(1);
        await _source.ObserveOrganizationAsync(_regular.TenantId);
        var warning = (await _findings.GetAsync(critical.Id))!;
        Assert.Equal("warning", warning.Severity);
        Assert.Contains(await _findings.EventsAsync(critical.Id), e => e.Kind == FindingEventKinds.SeverityChanged);
    }

    [Fact]
    public async Task OneOrganizationsCollectorSaysNothingAboutAnothers()
    {
        await CollectedAsync("local");
        await _registry.RecordAsync(_beta.TenantId, null, FindingSourceIds.Reports, false, "throttled", 1);

        var observed = await _source.ObserveAllAsync();
        var acme = Assert.Single(observed, o => o.Organization == "local");
        var beta = Assert.Single(observed, o => o.Organization == "other-msp");
        Assert.Null(acme.NotObserved);
        Assert.Equal(1, acme.Quiet);
        Assert.Equal("the last collection failed: throttled", beta.NotObserved);

        Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _regular.TenantId }));
        Assert.Empty(await _findings.ListAsync(new FindingFilter { TenantId = _beta.TenantId }));

        await CollectedAsync("other-msp");
        Assert.Equal(1, (await _source.ObserveOrganizationAsync(_beta.TenantId)).Quiet);
        Assert.Equal(Beta, Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _beta.TenantId })).Domain);
    }

    // ---- fixture -------------------------------------------------------------------------

    private sealed record Ids(string TenantId, string ClientId, string DomainId);

    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>The collector read the organization's mailbox, an hour ago unless said otherwise.</summary>
    private Task<bool> CollectedAsync(string organization, DateTimeOffset? at = null) =>
        _registry.RecordForOrganizationAsync(organization, FindingSourceIds.Reports, true, null, ReportsFindingSource.ExpectedEveryHours, at ?? Now.AddHours(-1));

    /// <summary>A receiver's report of the domain for the day ending at <paramref name="end"/>.</summary>
    private void Report(string organization, string domain, string reportId, DateTimeOffset end)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>receiver.example</org_name>
                <email>noreply@receiver.example</email>
                <report_id>{reportId}</report_id>
                <date_range><begin>{end.AddDays(-1).ToUnixTimeSeconds()}</begin><end>{end.ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;
        new ReportStore(_dbPath, organization).SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, "msg-" + reportId).GetAwaiter().GetResult();
    }

    /// <summary>A first report files each domain; one client is made and the domains filed under it.</summary>
    private void Onboard(string organization, string clientName, params string[] domains)
    {
        var store = new ReportStore(_dbPath, organization);
        foreach (var domain in domains) { Report(organization, domain, $"first-{domain}", new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero)); }
        var slug = store.CreateClientAsync(clientName).GetAwaiter().GetResult()!;
        foreach (var domain in domains) { store.AssignDomainAsync(domain, slug).GetAwaiter().GetResult(); }
    }

    /// <summary>When the client's reports count as stored, under the test's clock rather than the machine's.</summary>
    private async Task StampIngestedAsync(string clientId, DateTimeOffset at)
    {
        await using var db = await _files.OpenAsync(ClientScope.Client(clientId), write: true);
        await using var command = db.CreateCommand();
        command.CommandText = "UPDATE aggregate_reports SET ingested_at = $at";
        command.Parameters.AddWithValue("$at", at.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync();
    }

    private async Task<string> NewestReportIdAsync(string clientId, string domainId)
    {
        await using var db = await _files.OpenAsync(ClientScope.Client(clientId), ["aggregate_reports"]);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id FROM aggregate_reports WHERE domain_id = $domain ORDER BY date_end DESC, id LIMIT 1";
        command.Parameters.AddWithValue("$domain", domainId);
        return (string)(await command.ExecuteScalarAsync())!;
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
