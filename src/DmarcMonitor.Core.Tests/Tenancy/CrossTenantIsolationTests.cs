using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Rollout;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Tenancy;

/// <summary>
/// One install, two MSPs, and a domain name they both manage.
///
/// The schema allows it on purpose - UNIQUE(tenant_id, name) rather than
/// UNIQUE(name) - so that two organizations on one install can each look after
/// example.com for their own customer. Which means every query that resolves a
/// domain by NAME and not by name-and-organization answers with somebody
/// else's data, and does it silently.
///
/// That is exactly what happened. The zone-audit paste box on the domain page
/// read the whole book: an operator in one organization pasting a zone got the
/// other organization's DKIM selector names back in the findings, along with
/// its report counts and its domain list. It was proved with a two-tenant
/// database before it was fixed, and this is that proof kept.
///
/// Null means every organization, which is what a command-line run by the
/// operator wants. Nothing serving a signed-in person may pass null.
/// </summary>
public sealed class CrossTenantIsolationTests : IDisposable
{
    private const string SecretSelector = "orgb-private-selector";

    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-tenants-{Guid.NewGuid():N}.db");

    public CrossTenantIsolationTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        SeedAsync().GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    /// <summary>Two organizations, each managing a domain called example.com.</summary>
    private async Task SeedAsync()
    {
        const string when = "2026-09-20 00:00:00";

        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        async Task Run(string sql)
        {
            await using var command = db.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        await Run($"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','Org A','{when}','{when}'),('t-b','orgb','Org B','{when}','{when}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','ca','Client A','{when}','{when}'),('c-b','t-b','cb','Client B','{when}','{when}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','example.com','{when}','{when}'),
                     ('d-b','t-b','c-b','example.com','{when}','{when}');
            """);

        // Only organization B has reports. Everything below asks whether
        // organization A can see any of them.
        await Run($"""
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,
               date_begin,date_end,raw_hash,received_at,ingested_at,policy_p)
              VALUES ('r-b','t-b','c-b','d-b','google.com','rep-b',
                      '2026-09-01 00:00:00','{when}','hash','{when}','{when}','reject');
            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,
               dmarc_result,dkim_domain,dkim_selector,dkim_auth_result,header_from)
              VALUES ('r-b','t-b','c-b','d-b','{when}','192.0.2.1',10,
                      'pass','example.com','{SecretSelector}','pass','example.com');
            """);
    }

    // ---- the zone audit, which is the one reachable from a page ----------------

    [Fact]
    public async Task AZoneAuditForOneOrganizationCannotSeeAnothersSelectors()
    {
        var report = await new ZoneAuditor(databasePath: _dbPath, tenantId: "t-a")
            .RunAsync("$ORIGIN example.com.\n@ 3600 IN TXT \"v=spf1 -all\"\n", "example.com", offline: true);

        Assert.DoesNotContain(SecretSelector, report.Evidence.SeenSigning);
    }

    [Fact]
    public async Task AZoneAuditForOneOrganizationCannotSeeAnothersDomains()
    {
        // Not only a disclosure. The monitored list decides which reporting
        // authorizations are flagged as pointing at a domain nobody watches,
        // so another organization's domains silently change this one's
        // findings.
        var report = await new ZoneAuditor(databasePath: _dbPath, tenantId: "t-a")
            .RunAsync("$ORIGIN example.com.\n@ 3600 IN TXT \"v=spf1 -all\"\n", "example.com");

        Assert.All(report.Evidence.Monitored, d => Assert.Equal("example.com", d));
        Assert.Single(report.Evidence.Monitored);
    }

    [Fact]
    public async Task TheOrganizationThatOwnsTheDataStillSeesIt()
    {
        // An isolation fix that isolates everybody from their own data is not
        // a fix.
        var report = await new ZoneAuditor(databasePath: _dbPath, tenantId: "t-b")
            .RunAsync("$ORIGIN example.com.\n@ 3600 IN TXT \"v=spf1 -all\"\n", "example.com");

        Assert.Contains(SecretSelector, report.Evidence.SeenSigning);
    }

    [Fact]
    public async Task NoTenantMeansEveryTenant()
    {
        // What a command-line run by the operator gets, and what nothing
        // serving a signed-in person may ask for.
        var report = await new ZoneAuditor(databasePath: _dbPath)
            .RunAsync("$ORIGIN example.com.\n@ 3600 IN TXT \"v=spf1 -all\"\n", "example.com");

        Assert.Contains(SecretSelector, report.Evidence.SeenSigning);
        Assert.Equal(2, report.Evidence.Monitored.Count);
    }

    // ---- the same shape, everywhere else it appears ------------------------------

    [Fact]
    public async Task SelectorsSeenSigningAreScopedToOneOrganization()
    {
        var scanner = new DnsScanner(_dbPath);

        Assert.Empty(await scanner.SelectorsSeenSigningAsync("example.com", "t-a"));
        Assert.Single(await scanner.SelectorsSeenSigningAsync("example.com", "t-b"));
    }

    [Fact]
    public async Task TheReportsReplayedByTheSimulatorAreScopedToOneOrganization()
    {
        // Otherwise a simulation run for one organization answers with the
        // other's mail, and the number it prints is used to decide whether to
        // start rejecting a customer's mail.
        var service = new PolicySimulationService(_dbPath, "t-a");
        var other = new PolicySimulationService(_dbPath, "t-b");

        Assert.Empty(await service.RowsAsync("example.com", 90));
        Assert.NotEmpty(await other.RowsAsync("example.com", 90));
    }

    [Fact]
    public async Task ThePolicyInForceIsReadFromTheRightOrganization()
    {
        Assert.Null(await new PolicySimulationService(_dbPath, "t-a").CurrentAsync("example.com", 90));

        var theirs = await new PolicySimulationService(_dbPath, "t-b").CurrentAsync("example.com", 90);
        Assert.Equal("reject", theirs?.Policy);
    }

    [Fact]
    public async Task ReachabilityListsOnlyOneOrganizationsDomains()
    {
        var mine = await new ReachabilityService(_dbPath, tenantId: "t-a").RunAsync(domain: "example.com");
        var everyones = await new ReachabilityService(_dbPath).RunAsync(domain: "example.com");

        // One row each, but the counts behind them come from different books.
        Assert.Single(mine);
        Assert.Equal(0, mine[0].ReportsHeld);
        Assert.Equal(2, everyones.Count);
    }

    // ---- writes, not just reads ----------------------------------------------------

    [Fact]
    public async Task AReadingSavedForOneOrganizationLandsOnItsOwnDomainRow()
    {
        // The worst of the family, because it is a write. Resolving the name
        // without an organization took whichever row SQLite returned first, so
        // a scan run for one organization wrote its readings and DKIM
        // selectors onto the other's domain - leaving one of them reading
        // "never checked" for ever while the other was written twice.
        var store = new DnsSnapshotStore(_dbPath);

        await store.SaveAsync(
            "example.com",
            new PublishedRecords { Domain = "example.com", DmarcRecord = "v=DMARC1; p=none" },
            dkim: null,
            scopeTenantId: "t-a");

        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText = "SELECT domain_id FROM dns_snapshots";

        var landedOn = (string?)await command.ExecuteScalarAsync();
        Assert.Equal("d-a", landedOn);
    }
}
