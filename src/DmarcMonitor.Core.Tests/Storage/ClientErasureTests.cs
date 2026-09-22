using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Erasing a client, and being able to say truthfully that it is gone.
///
/// The only operation in this product that cannot be undone from inside it,
/// and the one whose failure mode is worst in both directions: erasing too
/// little means telling a customer their data is deleted when it is not, and
/// erasing too much means destroying somebody else's.
/// </summary>
public sealed class ClientErasureTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-erase-{Guid.NewGuid():N}.db");

    public ClientErasureTests()
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

    private async Task RunAsync(string sql)
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> ScalarAsync(string sql)
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0L);
    }

    /// <summary>Two organizations, each with a client, each with reports.</summary>
    private async Task SeedAsync()
    {
        const string when = "2026-09-20 00:00:00";

        await RunAsync($"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','Org A','{when}','{when}'),('t-b','orgb','Org B','{when}','{when}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','acme','Acme Corp','{when}','{when}'),
                     ('c-other','t-a','beta','Beta Ltd','{when}','{when}'),
                     ('c-b','t-b','gamma','Gamma Inc','{when}','{when}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','acme.com','{when}','{when}'),
                     ('d-a2','t-a','c-a','acme.net','{when}','{when}'),
                     ('d-other','t-a','c-other','beta.example','{when}','{when}'),
                     ('d-b','t-b','c-b','gamma.example','{when}','{when}');

            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r-a','t-a','c-a','d-a','google.com','ra','{when}','{when}','ha','{when}'),
                     ('r-other','t-a','c-other','d-other','google.com','ro','{when}','{when}','ho','{when}'),
                     ('r-b','t-b','c-b','d-b','google.com','rb','{when}','{when}','hb','{when}');

            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
              VALUES ('r-a','t-a','c-a','d-a','{when}','192.0.2.1',10,'pass'),
                     ('r-a','t-a','c-a','d-a','{when}','192.0.2.2',5,'fail'),
                     ('r-other','t-a','c-other','d-other','{when}','198.51.100.1',7,'pass'),
                     ('r-b','t-b','c-b','d-b','{when}','203.0.113.1',3,'pass');

            INSERT INTO dkim_selectors (id,tenant_id,client_id,domain_id,selector,first_seen,last_seen)
              VALUES ('s-a','t-a','c-a','d-a','selector1','{when}','{when}');
            """);
    }

    private ClientErasure Erasure() => new(_dbPath);

    // ---- a preview changes nothing ---------------------------------------------

    [Fact]
    public async Task APreviewCountsWithoutRemovingAnything()
    {
        var before = await ScalarAsync("SELECT COUNT(*) FROM aggregate_records");

        var preview = await Erasure().PreviewAsync("acme");

        Assert.NotNull(preview);
        Assert.False(preview.Applied);
        Assert.Equal("Acme Corp", preview.Name);
        Assert.Equal("orga", preview.Organization);
        Assert.Equal(["acme.com", "acme.net"], preview.Domains);
        Assert.Equal(before, await ScalarAsync("SELECT COUNT(*) FROM aggregate_records"));
    }

    [Fact]
    public async Task ThePreviewNamesEveryTableHoldingSomething()
    {
        var preview = await Erasure().PreviewAsync("acme");

        var tables = preview!.Rows.Select(r => r.Table).ToList();

        Assert.Contains("aggregate_records", tables);
        Assert.Contains("aggregate_reports", tables);
        Assert.Contains("domains", tables);
        Assert.Contains("dkim_selectors", tables);

        // Empty tables are left out: a list of forty tables with zero beside
        // thirty-six of them is a list nobody reads to the bottom.
        Assert.All(preview.Rows, r => Assert.True(r.Rows > 0));
    }

    [Fact]
    public async Task AClientThatDoesNotExistIsNullRatherThanAnError()
    {
        Assert.Null(await Erasure().PreviewAsync("nobody"));
    }

    // ---- erasing ------------------------------------------------------------------

    [Fact]
    public async Task ErasingRemovesEverythingBelongingToThatClient()
    {
        var result = await Erasure().ApplyAsync("acme", null, "matthew", null);

        Assert.NotNull(result);
        Assert.True(result.Applied);

        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'acme'"));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM domains WHERE client_id = 'c-a'"));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM aggregate_reports WHERE client_id = 'c-a'"));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM aggregate_records WHERE client_id = 'c-a'"));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM dkim_selectors WHERE client_id = 'c-a'"));
    }

    [Fact]
    public async Task AnotherClientInTheSameOrganizationIsUntouched()
    {
        await Erasure().ApplyAsync("acme", null, "matthew", null);

        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'beta'"));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM aggregate_records WHERE client_id = 'c-other'"));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM domains WHERE client_id = 'c-other'"));
    }

    [Fact]
    public async Task AnotherOrganizationIsUntouched()
    {
        await Erasure().ApplyAsync("acme", null, "matthew", null);

        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'gamma'"));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM aggregate_records WHERE client_id = 'c-b'"));
    }

    [Fact]
    public async Task ScopedToAnOrganizationItCannotReachAnothersClient()
    {
        // The worst possible version of the cross-tenant bug: erasure reaching
        // across an organization boundary. An operator in org A naming org B's
        // client must get "no such client", exactly as for one that does not
        // exist.
        Assert.Null(await Erasure().PreviewAsync("gamma", tenantId: "t-a"));

        var refused = await Erasure().ApplyAsync("gamma", "t-a", "matthew", null);

        Assert.Null(refused);
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'gamma'"));
    }

    [Fact]
    public async Task ScopedToItsOwnOrganizationItWorks()
    {
        // An isolation check that isolates everybody from their own data is
        // not a check.
        var result = await Erasure().ApplyAsync("gamma", "t-b", "matthew", null);

        Assert.NotNull(result);
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'gamma'"));
    }

    // ---- the record of the erasure survives it -------------------------------------

    [Fact]
    public async Task TheAuditLogKeepsTheRecordAndNotTheData()
    {
        var audit = new AuditLog(_dbPath);

        await Erasure().ApplyAsync("acme", "t-a", "matthew", audit);

        var entries = await audit.ListAsync("t-a");
        var erase = Assert.Single(entries, e => e.Action == "client.erase");

        Assert.Equal("matthew", erase.Actor);

        // The client's name is not the data that was erased, and proving a
        // request was honoured needs it. The reports are what had to go.
        Assert.Contains("Acme Corp", erase.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.1", erase.Detail ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task ApplyingWithoutSayingWhoIsRefused()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => Erasure().ApplyAsync("acme", null, "  ", null));

        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM clients WHERE slug = 'acme'"));
    }

    // ---- the guarantee -----------------------------------------------------------------

    [Fact]
    public async Task NoRowAnywhereStillCarriesTheErasedClientsId()
    {
        // The property the whole thing rests on, checked the way the service
        // checks it: every table in the schema with a client_id column, not a
        // list written down once and gone stale.
        await Erasure().ApplyAsync("acme", null, "matthew", null);

        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        var tables = await ClientErasure.TablesWithClientIdAsync(db, default);
        Assert.NotEmpty(tables);

        foreach (var table in tables)
        {
            await using var command = db.CreateCommand();
            command.CommandText = $"SELECT COUNT(*) FROM {table} WHERE client_id = 'c-a'";
            Assert.Equal(0L, Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0L));
        }
    }

    [Fact]
    public async Task TheTableListIsReadFromTheSchemaRatherThanHardcoded()
    {
        // Nineteen tables cascade from clients today and the count only goes
        // up. A hand-written list goes stale, and the failure mode of a stale
        // list is a table full of an erased customer's data that nobody
        // counted and nobody checked.
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        var tables = await ClientErasure.TablesWithClientIdAsync(db, default);

        Assert.Contains("aggregate_records", tables);
        Assert.Contains("aggregate_reports", tables);
        Assert.Contains("domains", tables);
        Assert.DoesNotContain("tenants", tables);      // no client_id
        Assert.DoesNotContain("audit_log", tables);    // deliberately none, so it survives
    }

    [Fact]
    public async Task TheTotalMatchesWhatWasCounted()
    {
        var preview = await Erasure().PreviewAsync("acme");
        var result = await Erasure().ApplyAsync("acme", null, "matthew", null);

        Assert.Equal(preview!.Total, result!.Total);
        Assert.True(result.Total > 0);
    }

    [Fact]
    public async Task RefusesAnEmptyDatabasePathOrClient()
    {
        Assert.Throws<ArgumentException>(() => new ClientErasure("  "));

        // Awaited. Without it the assertion never ran and this passed whatever
        // PreviewAsync did - caught by xunit's analyzers on the version bump,
        // not by the test failing.
        await Assert.ThrowsAsync<ArgumentException>(() => Erasure().PreviewAsync("  "));
    }
}
