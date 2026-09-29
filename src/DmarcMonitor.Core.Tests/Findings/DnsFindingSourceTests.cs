using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Findings;

/// <summary>
/// The nightly DNS scan feeding the findings lifecycle through the snapshot
/// store: a change is a finding pointing at its drift event, the same drift
/// another night is the same finding seen again, the record back as it was
/// resolves it, a further change moves it, and a failed read clears nothing.
/// </summary>
public sealed class DnsFindingSourceTests : IDisposable
{
    private const string Domain = "acme.example";
    private const string Original = "v=DMARC1; p=quarantine; rua=mailto:d@msp.example";
    private const string Loosened = "v=DMARC1; p=none; rua=mailto:d@msp.example";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-dnsfindings-{Guid.NewGuid():N}.db");
    private readonly DnsSnapshotStore _dns;
    private readonly FindingStore _findings;
    private readonly Ids _acme;

    public DnsFindingSourceTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        Onboard("local", Domain, "r-1", "Acme Corp");
        _dns = new DnsSnapshotStore(_dbPath);
        _findings = new FindingStore(_dbPath);
        _acme = IdsAsync("local", "acme-corp", Domain).GetAwaiter().GetResult();
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    [Fact]
    public async Task ALoosenedPolicyIsAWeakenedFindingPointingAtItsDriftEvent()
    {
        await _dns.SaveAsync(Domain, Reading());
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));

        var finding = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));

        Assert.Equal(FindingTypes.DmarcPolicyWeakened, finding.Type);
        Assert.Equal("policy_loosened", finding.Rule);
        Assert.Equal("critical", finding.Severity);
        Assert.StartsWith("DMARC: p=quarantine → p=none", finding.Title, StringComparison.Ordinal);
        Assert.Equal(DnsFindingSource.DedupKey(_acme.DomainId, "dmarc"), finding.DedupKey);
        Assert.Equal(DnsFindingSource.RecordRef(Original), finding.ExpectedRef);
        Assert.Equal(SourceStates.Active, finding.SourceState);
        Assert.Equal(Domain, finding.Domain);
        Assert.Equal("Acme Corp", finding.ClientName);

        // The evidence is the drift event, in the client's file.
        var drift = Assert.Single(await new DnsDriftStore(_dbPath).ListAsync(_acme.TenantId));
        Assert.Equal("drift:" + drift.Id, finding.EvidenceRef);
        Assert.Equal(Loosened, drift.NewValue);
    }

    [Fact]
    public async Task TheRecordTextStaysInTheClientsFileAndNeverReachesTheOrganizationsDatabase()
    {
        await _dns.SaveAsync(Domain, Reading());
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));

        // Read as bytes rather than through a query, journal included:
        // whatever a copied database or a backup of the organization's file
        // would carry, this is it.
        Assert.DoesNotContain("rua=mailto:d@msp.example", OrganizationFileText(), StringComparison.Ordinal);
        Assert.Contains("rua=mailto:d@msp.example", ClientFilesText(), StringComparison.Ordinal);
        Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
    }

    [Fact]
    public async Task TheSameDriftAnotherNightIsTheSameFindingSeenAgain()
    {
        await _dns.SaveAsync(Domain, Reading());
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));

        var finding = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(3, finding.ObservationCount);
        Assert.Equal(SourceStates.Active, finding.SourceState);
        Assert.Equal(FindingEventKinds.Observed, Assert.Single(await _findings.EventsAsync(finding.Id)).Kind);
    }

    [Fact]
    public async Task TheRecordBackAsItWasResolvesTheFindingAndAReturnReopensIt()
    {
        await _dns.SaveAsync(Domain, Reading());
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));
        await _dns.SaveAsync(Domain, Reading());

        var resolved = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(SourceStates.Resolved, resolved.SourceState);
        Assert.NotNull(resolved.SourceResolvedAt);
        Assert.False(resolved.InQueue);
        // The change back is not a second finding: it is what resolved the first.
        Assert.Equal(2, (await new DnsDriftStore(_dbPath).ListAsync(_acme.TenantId)).Count);

        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));

        var reopened = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(resolved.Id, reopened.Id);
        Assert.Equal(SourceStates.Active, reopened.SourceState);
        Assert.Equal(1, reopened.ReopenedCount);
        Assert.Equal(AnalystStates.Unreviewed, reopened.AnalystState);
        Assert.Contains(await _findings.EventsAsync(reopened.Id), e => e.Kind == FindingEventKinds.Reopened);
    }

    [Fact]
    public async Task AFurtherChangeMovesTheFindingRatherThanRaisingAnother()
    {
        await _dns.SaveAsync(Domain, Reading(dmarc: "v=DMARC1; p=quarantine; pct=100; rua=mailto:d@msp.example"));
        await _dns.SaveAsync(Domain, Reading(dmarc: "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@msp.example"));

        var changed = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(FindingTypes.DmarcPolicyChanged, changed.Type);
        Assert.Equal("pct_lowered", changed.Rule);
        Assert.Equal("warning", changed.Severity);

        await _dns.SaveAsync(Domain, Reading(dmarc: null));

        var weakened = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(changed.Id, weakened.Id);
        Assert.Equal(FindingTypes.DmarcPolicyWeakened, weakened.Type);
        Assert.Equal("record_removed", weakened.Rule);
        Assert.Equal("critical", weakened.Severity);
        Assert.Equal(changed.ExpectedRef, weakened.ExpectedRef);
        var kinds = (await _findings.EventsAsync(weakened.Id)).Select(e => e.Kind).ToList();
        Assert.Contains(FindingEventKinds.SeverityChanged, kinds);
        Assert.Contains(FindingEventKinds.TypeChanged, kinds);

        // Only the record as it was before the first change resolves it.
        await _dns.SaveAsync(Domain, Reading(dmarc: "v=DMARC1; p=quarantine; pct=100; rua=mailto:d@msp.example"));
        Assert.Equal(SourceStates.Resolved, Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId })).SourceState);
    }

    [Fact]
    public async Task AFailedReadMarksTheDomainsFindingsUnknownAndResolvesNothing()
    {
        await _dns.SaveAsync(Domain, Reading());
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));

        await _dns.SaveAsync(Domain, new PublishedRecords { Domain = Domain, LookupFailed = true });

        var unknown = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(SourceStates.Unknown, unknown.SourceState);
        Assert.Null(unknown.SourceResolvedAt);
        Assert.True(unknown.InQueue);
        Assert.Contains(await _findings.EventsAsync(unknown.Id), e => e.Kind == FindingEventKinds.SourceUnknown);

        // Seen again once the lookup works: the same finding, active.
        await _dns.SaveAsync(Domain, Reading(dmarc: Loosened));
        var back = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(unknown.Id, back.Id);
        Assert.Equal(SourceStates.Active, back.SourceState);
    }

    [Fact]
    public async Task TwoSpfRecordsAreInvalidUntilOneIsLeft()
    {
        const string spf = "v=spf1 include:_spf.mail.example -all";
        await _dns.SaveAsync(Domain, Reading(spf: spf));
        await _dns.SaveAsync(Domain, new PublishedRecords { Domain = Domain, SpfRecords = [spf, "v=spf1 ip4:192.0.2.1 -all"], DmarcRecord = Original });

        var invalid = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(FindingTypes.SpfInvalid, invalid.Type);
        Assert.Equal("multiple_records", invalid.Rule);
        Assert.Equal("critical", invalid.Severity);
        Assert.Equal(DnsFindingSource.DedupKey(_acme.DomainId, "spf"), invalid.DedupKey);

        await _dns.SaveAsync(Domain, Reading(spf: spf));
        Assert.Equal(SourceStates.Resolved, Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId })).SourceState);
    }

    [Fact]
    public async Task AWithdrawnTlsRptRecordIsDriftAndItsReturnResolvesIt()
    {
        await _dns.SaveAsync(Domain, Reading() with { TlsRptRecord = "v=TLSRPTv1; rua=mailto:tls@msp.example" });
        await _dns.SaveAsync(Domain, Reading());

        var drift = Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId }));
        Assert.Equal(FindingTypes.DnsDrift, drift.Type);
        Assert.Equal("record_removed", drift.Rule);
        Assert.Equal("warning", drift.Severity);
        Assert.Equal(DnsFindingSource.DedupKey(_acme.DomainId, "tls-rpt"), drift.DedupKey);

        await _dns.SaveAsync(Domain, Reading() with { TlsRptRecord = "v=TLSRPTv1; rua=mailto:tls@msp.example" });
        Assert.Equal(SourceStates.Resolved, Assert.Single(await _findings.ListAsync(new FindingFilter { TenantId = _acme.TenantId })).SourceState);
    }

    [Fact]
    public async Task TheScanRecordsItsHealthPerClient()
    {
        var scanner = new DnsScanner(_dbPath);
        var registry = new FindingSourceRegistry(_dbPath);

        await scanner.CompleteAsync([Result(Domain, DnsCheckStatus.Ok)]);
        var healthy = Assert.Single(await registry.HealthAsync(_acme.TenantId));
        Assert.Equal(SourceHealth.Healthy, healthy.Health);
        Assert.Equal(FindingSourceIds.DnsScan, healthy.Source.Kind);
        Assert.Equal("acme-corp", healthy.Source.ClientSlug);
        Assert.Equal(DnsFindingSource.ExpectedEveryHours, healthy.Source.ExpectedEveryHours);

        await scanner.CompleteAsync([Result(Domain, DnsCheckStatus.Failed), Result("other.example", DnsCheckStatus.Ok)]);
        var degraded = Assert.Single(await registry.HealthAsync(_acme.TenantId));
        Assert.Equal(SourceHealth.Degraded, degraded.Health);
        Assert.Equal("1 of 2 domains could not be read: acme.example", degraded.Source.LastError);

        // A domain that does not exist answered; a reading that was not stored belongs to nobody.
        await scanner.CompleteAsync([Result(Domain, DnsCheckStatus.NoSuchDomain), new ScanResult("prospect.example", DnsCheckStatus.Ok, Stored: false, Changed: false, Selectors: 0)]);
        Assert.Equal(SourceHealth.Healthy, Assert.Single(await registry.HealthAsync(_acme.TenantId)).Health);
    }

    // ---- fixture -------------------------------------------------------------------------

    private sealed record Ids(string TenantId, string ClientId, string DomainId);

    private ScanResult Result(string domain, DnsCheckStatus status) =>
        new(domain, status, Stored: true, Changed: false, Selectors: 0) { DomainId = _acme.DomainId, TenantId = _acme.TenantId, ClientId = _acme.ClientId };

    private static PublishedRecords Reading(string? dmarc = Original, string spf = "v=spf1 include:_spf.mail.example -all") => new()
    {
        Domain = Domain,
        SpfRecords = [spf],
        DmarcRecord = dmarc,
        SpfLookups = 2,
    };

    private string OrganizationFileText() => FileText(_dbPath) + FileText(_dbPath + "-wal");

    private string ClientFilesText()
    {
        var folder = ClientDatabases.FolderFor(_dbPath);
        return string.Concat(Directory.EnumerateFiles(folder).Select(FileText));
    }

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
