using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Reading the facts the health check judges, out of a real database.
///
/// The counting is the part worth pinning. Written with a join across domains
/// and reports, this reported "32,164 reports stored today" against a real
/// database holding 1,892 - the join multiplied every report by the seventeen
/// domains the organization holds. It is exactly the shape of wrong that reads
/// as plausible: a big number where a big number belongs.
/// </summary>
public sealed class HealthServiceTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-health-{Guid.NewGuid():N}.db");

    private static readonly DateTimeOffset Now = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    public HealthServiceTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    /// <summary>SQL written for one database, split into client files afterwards.</summary>
    private Task RunAsync(string sql) => SingleDatabase.ExecuteAsync(_dbPath, sql);

    /// <summary>One organization, several domains, and reports spread across them.</summary>
    private async Task SeedAsync(string org, int domains, int reportsPerDomain, DateTimeOffset ingested)
    {
        var at = ingested.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        var sql = new System.Text.StringBuilder();

        sql.Append($"INSERT INTO tenants (id,slug,name,created_at,updated_at) VALUES ('t-{org}','{org}','{org}','{at}','{at}');");
        sql.Append($"INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at) VALUES ('c-{org}','t-{org}','c','C','{at}','{at}');");

        for (var d = 0; d < domains; d++)
        {
            sql.Append($"INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at) "
                     + $"VALUES ('d-{org}-{d}','t-{org}','c-{org}','{org}{d}.example','{at}','{at}');");

            for (var r = 0; r < reportsPerDomain; r++)
            {
                sql.Append($"INSERT INTO aggregate_reports "
                         + "(id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at) "
                         + $"VALUES ('r-{org}-{d}-{r}','t-{org}','c-{org}','d-{org}-{d}','google.com','ext-{d}-{r}',"
                         + $"'{at}','{at}','h-{d}-{r}','{at}');");
            }
        }

        await RunAsync(sql.ToString());
    }

    [Fact]
    public async Task CountsReportsOnceRatherThanOncePerDomain()
    {
        // 3 domains x 4 reports = 12. A join would say 36.
        await SeedAsync("nrg", domains: 3, reportsPerDomain: 4, ingested: Now.AddHours(-2));

        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);
        var org = Assert.Single(facts.Collection);

        Assert.Equal("nrg", org.Organization);
        Assert.Equal(3, org.Domains);
        Assert.Equal(12, org.StoredLastDay);
    }

    [Fact]
    public async Task OnlyCountsWhatArrivedInTheLastDay()
    {
        await SeedAsync("nrg", domains: 2, reportsPerDomain: 3, ingested: Now.AddDays(-5));

        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);
        var org = Assert.Single(facts.Collection);

        Assert.Equal(0, org.StoredLastDay);
        Assert.Equal(Now.AddDays(-5), org.LastStored);
    }

    [Fact]
    public async Task EachOrganizationIsCountedSeparately()
    {
        await SeedAsync("nrg", domains: 3, reportsPerDomain: 2, ingested: Now.AddHours(-1));
        await SeedAsync("nextlayersec", domains: 1, reportsPerDomain: 5, ingested: Now.AddHours(-1));

        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);

        Assert.Equal(2, facts.Collection.Count);
        Assert.Equal(5, facts.Collection.Single(c => c.Organization == "nextlayersec").StoredLastDay);
        Assert.Equal(6, facts.Collection.Single(c => c.Organization == "nrg").StoredLastDay);
    }

    [Fact]
    public async Task AnOrganizationWithDomainsAndNoReportsIsStillListed()
    {
        // The row most worth having: a collector that has never worked.
        await SeedAsync("nrg", domains: 2, reportsPerDomain: 0, ingested: Now);

        var org = Assert.Single((await new HealthService(_dbPath).GatherAsync(null, Now)).Collection);

        Assert.Equal(2, org.Domains);
        Assert.Null(org.LastStored);
        Assert.Equal(0, org.StoredLastDay);
    }

    [Fact]
    public async Task AnOrganizationWithNoDomainsIsLeftOut()
    {
        const string at = "2026-09-22 00:00:00";
        await RunAsync($"INSERT INTO tenants (id,slug,name,created_at,updated_at) VALUES ('t','empty','E','{at}','{at}');");

        Assert.Empty((await new HealthService(_dbPath).GatherAsync(null, Now)).Collection);
    }

    [Fact]
    public async Task ADomainWithHistoryThatStoppedIsQuietAndOneWithoutIsNot()
    {
        await SeedAsync("nrg", domains: 1, reportsPerDomain: 2, ingested: Now.AddDays(-30));

        // A domain that never had anything: onboarding, not a domain gone quiet.
        const string at = "2026-09-22 00:00:00";
        await RunAsync("INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at) "
                     + $"VALUES ('d-new','t-nrg','c-nrg','brand-new.example','{at}','{at}');");

        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);

        Assert.Equal("nrg0.example", Assert.Single(facts.Quiet).Domain);
    }

    [Fact]
    public async Task ADomainReportedOnRecentlyIsNotQuiet()
    {
        await SeedAsync("nrg", domains: 1, reportsPerDomain: 1, ingested: Now.AddHours(-2));

        Assert.Empty((await new HealthService(_dbPath).GatherAsync(null, Now)).Quiet);
    }

    [Fact]
    public async Task ANameHeldByTwoOrganizationsIsFound()
    {
        const string at = "2026-09-22 00:00:00";
        await RunAsync($"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','A','{at}','{at}'),('t-b','orgb','B','{at}','{at}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','c','C','{at}','{at}'),('c-b','t-b','c','C','{at}','{at}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','shared.example','{at}','{at}'),
                     ('d-b','t-b','c-b','shared.example','{at}','{at}'),
                     ('d-c','t-a','c-a','only-mine.example','{at}','{at}');
            """);

        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);

        Assert.Equal("shared.example", Assert.Single(facts.HeldTwice));
    }

    // ---- backups ----------------------------------------------------------------

    [Fact]
    public void TheNewestBackupIsReadFromTheNameNotTheTimestamp()
    {
        // A backup's whole purpose is to be copied elsewhere, and copying
        // resets an mtime - so a set synced from another machine would all
        // look as though it was taken at once, and a stale set would look
        // fresh.
        var dir = Path.Combine(Path.GetTempPath(), $"dmarc-bk-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        try
        {
            foreach (var name in new[] { "dmarc-20260901-032000.bak", "dmarc-20260920-032000.bak" })
            {
                File.WriteAllText(Path.Combine(dir, name), "");
            }

            // The older name, written last, so mtime order is the reverse of name order.
            Assert.Equal(
                new DateTimeOffset(2026, 9, 20, 3, 20, 0, TimeSpan.Zero),
                HealthService.NewestBackup(dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ADirectoryWithNothingOfOursInItReadsAsNoBackup()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"dmarc-bk-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        try
        {
            File.WriteAllText(Path.Combine(dir, "notes.txt"), "");
            File.WriteAllText(Path.Combine(dir, "dmarc-not-a-date.bak"), "");

            Assert.Null(HealthService.NewestBackup(dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ADirectoryThatDoesNotExistReadsAsNoBackup()
    {
        Assert.Null(HealthService.NewestBackup(Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}")));
    }

    [Fact]
    public async Task NoBackupDirectoryMeansNothingIsConcludedAboutBackups()
    {
        var facts = await new HealthService(_dbPath).GatherAsync(null, Now);

        Assert.Null(facts.BackupDirectory);
        Assert.Null(facts.LastBackup);
    }

    [Fact]
    public void RefusesAnEmptyDatabasePath()
    {
        Assert.Throws<ArgumentException>(() => new HealthService("  "));
    }
}
