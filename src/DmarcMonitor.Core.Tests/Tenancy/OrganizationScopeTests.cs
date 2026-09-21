using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Domains;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Rollout;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Tenancy;

/// <summary>
/// Two organizations in one database, and every read that must not cross
/// between them.
///
/// The property: whatever an NRG person asks, the answer contains nothing of
/// NextLayerSec's. Asked without a scope - which only the master and the
/// command line do - the answer contains both.
/// </summary>
public sealed class OrganizationScopeTests : IAsyncLifetime, IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-scope-{Guid.NewGuid():N}.db");

    private string _nrg = "";
    private string _nls = "";

    public async Task InitializeAsync()
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        var orgs = new OrganizationStore(_dbPath);
        var nls = await orgs.CreateAsync("NextLayerSec");

        // NRG's domain arrives through NRG's collector, NextLayerSec's through
        // its own. Each store files new domains under its organization.
        var nrgStore = new ReportStore(_dbPath);
        var nlsStore = new ReportStore(_dbPath, "nextlayersec");

        await nrgStore.SaveAggregateAsync(Report("acme.com", "192.0.2.10", 100, 5), "nrg", null);
        await nlsStore.SaveAggregateAsync(Report("cornerpost.example", "198.51.100.7", 40, 8), "nls", null);

        var acme = await nrgStore.CreateClientAsync("Acme Corp");
        await nrgStore.AssignDomainAsync("acme.com", acme!);

        var corner = await nlsStore.CreateClientAsync("Corner Post");
        await nlsStore.AssignDomainAsync("cornerpost.example", corner!);

        _nrg = (await orgs.GetAsync(ReportStore.DefaultTenantSlug))!.Id;
        _nls = nls!.Id;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task TriageShowsOneOrganizationsDomainsOrAll()
    {
        var triage = new TriageService(_dbPath);

        var nrg = await triage.GetAsync(30, _nrg);
        Assert.Equal(["acme.com"], nrg.Select(r => r.Domain));
        Assert.Equal("acme-corp", nrg[0].ClientSlug);

        var nls = await triage.GetAsync(30, _nls);
        Assert.Equal(["cornerpost.example"], nls.Select(r => r.Domain));
        Assert.Equal("NextLayerSec", nls[0].Organization);

        var all = await triage.GetAsync(30);
        Assert.Equal(2, all.Count);

        // The scope that matches nothing, for somebody with no access.
        Assert.Empty(await triage.GetAsync(30, OrganizationAccess.NoAccessTenantId));
    }

    [Fact]
    public async Task ADomainOfAnotherOrganizationDoesNotExist()
    {
        var detail = new DomainDetailService(_dbPath);

        Assert.NotNull(await detail.GetAsync("acme.com", 30, _nrg));
        Assert.Null(await detail.GetAsync("cornerpost.example", 30, _nrg));
        Assert.NotNull(await detail.GetAsync("cornerpost.example", 30, _nls));
        Assert.NotNull(await detail.GetAsync("cornerpost.example", 30));
    }

    [Fact]
    public async Task TheChartsCountOneOrganizationsMail()
    {
        var series = new TimeSeriesService(_dbPath);

        Assert.Equal(105, (await series.BreakdownAsync(tenantId: _nrg)).Total);
        Assert.Equal(48, (await series.BreakdownAsync(tenantId: _nls)).Total);
        Assert.Equal(153, (await series.BreakdownAsync()).Total);

        Assert.Equal(105, (await series.EstateAsync(30, _nrg)).Sum(p => p.Messages));
        Assert.Equal((1, 0), await series.DomainActivityAsync(30, _nrg));
        Assert.Equal((2, 0), await series.DomainActivityAsync(30));

        var sparks = await series.PerDomainAsync(30, _nls);
        Assert.Equal(["cornerpost.example"], sparks.Keys);

        var sources = await series.SourcesAsync(tenantId: _nrg);
        Assert.All(sources, s => Assert.NotEqual("cornerpost.example", s.Source));
    }

    [Fact]
    public async Task FailingSourcesNeverCrossOrganizations()
    {
        // Across an organization's clients is the page's purpose; across
        // organizations would be one company reading another's threat data.
        var correlation = new CorrelationService(_dbPath);

        var nrg = await correlation.GetFailingSourcesAsync(30, tenantId: _nrg);
        Assert.Equal(["192.0.2.10"], nrg.Select(s => s.SourceIp));

        var all = await correlation.GetFailingSourcesAsync(30);
        Assert.Equal(2, all.Count);
    }

    [Fact]
    public async Task ClientsAndUnassignedAreListedPerOrganization()
    {
        var store = new ReportStore(_dbPath);

        Assert.Equal(["acme-corp"], (await store.GetClientsAsync(_nrg)).Where(c => c.Domains > 0).Select(c => c.Slug));
        Assert.Equal(["corner-post"], (await store.GetClientsAsync(_nls)).Where(c => c.Domains > 0).Select(c => c.Slug));
        Assert.Contains((await store.GetClientsAsync()).Select(c => c.Slug), s => s == "corner-post");

        Assert.Equal(["cornerpost.example"], (await store.GetDomainsAsync(_nls)).Select(d => d.Domain));
        Assert.Equal("NextLayerSec", (await store.GetDomainsAsync(_nls))[0].OrganizationName);
    }

    [Fact]
    public async Task AClientReportBelongsToItsOrganization()
    {
        var builder = new ClientReportBuilder(_dbPath);
        var period = ReportPeriod.MonthEnding(DateTimeOffset.UtcNow);

        Assert.NotNull(await builder.BuildAsync("corner-post", period, tenantId: _nls));
        Assert.Null(await builder.BuildAsync("corner-post", period, tenantId: _nrg));
        Assert.Equal(["acme-corp"], (await builder.GetClientsAsync(_nrg)).Select(c => c.Slug).Where(s => s != ReportStore.UnassignedClientSlug));
    }

    [Fact]
    public async Task AssigningToAnotherOrganizationsClientMovesTheDomainAndItsHistory()
    {
        // The one way a domain changes organization: somebody who can see
        // both files it under the other's client.
        var store = new ReportStore(_dbPath);

        Assert.Equal(ReportStore.AssignOutcome.Assigned, await store.AssignDomainAsync("acme.com", "corner-post"));

        Assert.Empty(await new TriageService(_dbPath).GetAsync(30, _nrg));
        var moved = await new TriageService(_dbPath).GetAsync(30, _nls);
        Assert.Equal(2, moved.Count);
        Assert.Equal(105, moved.Single(r => r.Domain == "acme.com").Messages);

        // Every table that carries the domain now says NextLayerSec.
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        await db.OpenAsync();
        foreach (var table in ReportStore.DomainScopedTables)
        {
            await using var count = db.CreateCommand();
            count.CommandText = $"""
                SELECT COUNT(*) FROM {table} t
                JOIN domains d ON d.id = t.domain_id
                WHERE d.name = 'acme.com' AND t.tenant_id <> $nls
                """;
            count.Parameters.AddWithValue("$nls", _nls);
            Assert.Equal(0L, Convert.ToInt64(await count.ExecuteScalarAsync()));
        }
    }

    [Fact]
    public async Task AScopedAssignCannotReachAnotherOrganizationsDomain()
    {
        // A NextLayerSec person naming an NRG domain gets "no such domain",
        // exactly as they would for a domain that does not exist.
        var store = new ReportStore(_dbPath);

        Assert.Equal(ReportStore.AssignOutcome.DomainNotFound, await store.AssignDomainAsync("acme.com", "corner-post", _nls));
        Assert.Single(await new TriageService(_dbPath).GetAsync(30, _nrg));
    }

    [Fact]
    public async Task UnassignedIsPerOrganization()
    {
        var nrgStore = new ReportStore(_dbPath);
        var nlsStore = new ReportStore(_dbPath, "nextlayersec");
        await nrgStore.SaveAggregateAsync(Report("new-nrg.example", "192.0.2.11", 1, 0), "a", null);
        await nlsStore.SaveAggregateAsync(Report("new-nls.example", "198.51.100.8", 1, 0), "b", null);

        Assert.Equal(["new-nrg.example"], await nrgStore.GetUnassignedDomainsAsync(_nrg));
        Assert.Equal(["new-nls.example"], await nrgStore.GetUnassignedDomainsAsync(_nls));
        Assert.Equal(2, (await nrgStore.GetUnassignedDomainsAsync()).Count);
    }

    [Fact]
    public async Task AKnownDomainKeepsItsOrganizationWhicheverCollectorSeesIt()
    {
        // NextLayerSec's collector receiving a report for an NRG domain must
        // not pull it across.
        var nlsStore = new ReportStore(_dbPath, "nextlayersec");
        await nlsStore.SaveAggregateAsync(Report("acme.com", "192.0.2.12", 7, 0), "again", null);

        var nrg = await new TriageService(_dbPath).GetAsync(30, _nrg);
        Assert.Equal(112, Assert.Single(nrg).Messages);
    }

    private static AggregateReport Report(string domain, string ip, int passing, int failing)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin><end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>{ip}</source_ip><count>{passing}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
              <record>
                <row><source_ip>{ip}</source_ip><count>{Math.Max(failing, 0)}</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>fail</result></dkim><spf><domain>{domain}</domain><result>fail</result></spf></auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException(parsed.Error); }
        return parsed.Report!;
    }
}
