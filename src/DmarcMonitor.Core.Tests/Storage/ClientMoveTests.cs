using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Renaming a client, and moving one into another organization.
///
/// The move is the operation an install needs and did not have. A client can
/// be created in an organization; nothing could move one afterwards - and
/// everybody imports reports before they think about structure, so everybody's
/// customers start in the default organization with no way out.
///
/// It is also the operation with the worst failure mode in this codebase.
/// tenant_id is denormalized onto every scoped table because that is what
/// every read filters on, so a move that updates the clients row and stops
/// leaves the customer's whole history answering to the organization they just
/// left: invisible from the new one, still counted by the old one, and looking
/// like a customer who has never sent mail.
/// </summary>
public sealed class ClientMoveTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-move-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;
    private readonly OrganizationStore _organizations;

    public ClientMoveTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        _organizations = new OrganizationStore(_dbPath);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private async Task<string> SeedAsync(string domain, string clientName)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}</begin>
                            <end>{DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.5</source_ip><count>12</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results>
                  <dkim><domain>{domain}</domain><result>pass</result></dkim>
                  <spf><domain>{domain}</domain><result>pass</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);

        var slug = await _store.CreateClientAsync(clientName);
        await _store.AssignDomainAsync(domain, slug!);
        return slug!;
    }

    private async Task<long> RowsInAsync(string table, string tenantId)
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table} WHERE tenant_id = $t";
        command.Parameters.AddWithValue("$t", tenantId);
        return (long)(await command.ExecuteScalarAsync() ?? 0L);
    }

    private async Task<string> TenantIdAsync(string slug) =>
        (await _organizations.GetAsync(slug))!.Id;

    // ---- rename --------------------------------------------------------------

    /// <summary>
    /// "Dakota Valley railRoad" was on every report that customer received
    /// and could not be corrected anywhere in this product.
    /// </summary>
    [Fact]
    public async Task RenamesAClientWithoutTouchingItsSlug()
    {
        var slug = await SeedAsync("acme.example", "Dakota Valley railRoad");

        Assert.True(await _store.RenameClientAsync(slug, "Dakota Valley Railroad"));

        var client = (await _store.GetClientsAsync()).Single(c => c.Slug == slug);
        Assert.Equal("Dakota Valley Railroad", client.Name);

        // The slug is printed in report filenames and has been sent to the
        // customer, so it is permanent by design and must survive a rename.
        Assert.Equal(slug, client.Slug);
    }

    [Fact]
    public async Task WillNotRenameTheUnassignedBucket()
    {
        await SeedAsync("acme.example", "Acme");

        Assert.False(await _store.RenameClientAsync(ReportStore.UnassignedClientSlug, "Anything"));
    }

    [Fact]
    public async Task RenamingAClientThatIsNotThereSaysSo()
    {
        Assert.False(await _store.RenameClientAsync("no-such-client", "Whatever"));
    }

    // ---- move ----------------------------------------------------------------

    /// <summary>
    /// The one that matters. Everything the customer has must arrive with
    /// them.
    /// </summary>
    [Fact]
    public async Task TakesTheDomainsAndTheReportsWithIt()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");
        var from = await TenantIdAsync(ReportStore.DefaultTenantSlug);

        var nrg = await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");
        Assert.NotNull(nrg);

        Assert.Equal(ReportStore.MoveOutcome.Moved, await _store.MoveClientAsync(slug, "nrg"));

        var to = await TenantIdAsync("nrg");

        // Nothing of this customer's may answer to the old organization.
        foreach (var table in new[] { "domains", "aggregate_reports", "aggregate_records" })
        {
            Assert.Equal(0, await RowsInAsync(table, from));
            Assert.True(await RowsInAsync(table, to) > 0, $"{table} did not come with the client");
        }
    }

    /// <summary>
    /// And it is visible from the new organization by the ordinary scoped
    /// read, which is the thing an operator actually experiences.
    /// </summary>
    [Fact]
    public async Task TheClientIsVisibleFromItsNewOrganizationAndNotTheOld()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");
        var from = await TenantIdAsync(ReportStore.DefaultTenantSlug);
        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");

        await _store.MoveClientAsync(slug, "nrg");
        var to = await TenantIdAsync("nrg");

        Assert.Contains(await _store.GetClientsAsync(to), c => c.Slug == slug);
        Assert.DoesNotContain(await _store.GetClientsAsync(from), c => c.Slug == slug);
    }

    [Fact]
    public async Task RefusesAnOrganizationThatDoesNotExist()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");

        Assert.Equal(ReportStore.MoveOutcome.OrganizationNotFound,
            await _store.MoveClientAsync(slug, "no-such-org"));
    }

    [Fact]
    public async Task RefusesAClientThatDoesNotExist()
    {
        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");

        Assert.Equal(ReportStore.MoveOutcome.ClientNotFound,
            await _store.MoveClientAsync("no-such-client", "nrg"));
    }

    [Fact]
    public async Task SaysSoRatherThanPretendingWhenItIsAlreadyThere()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");

        Assert.Equal(ReportStore.MoveOutcome.AlreadyThere,
            await _store.MoveClientAsync(slug, ReportStore.DefaultTenantSlug));
    }

    /// <summary>
    /// Slugs are unique within an organization and permanent, so a collision
    /// has to be found before anything moves rather than discovered after.
    /// </summary>
    [Fact]
    public async Task RefusesWhenTheDestinationAlreadyHasThatSlug()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");

        var nrg = await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");
        Assert.NotNull(nrg);
        await new ReportStore(_dbPath, "nrg").CreateClientAsync("Acme Corp");

        Assert.Equal(ReportStore.MoveOutcome.SlugTaken,
            await _store.MoveClientAsync(slug, "nrg", await TenantIdAsync(ReportStore.DefaultTenantSlug)));
    }

    /// <summary>
    /// Every organization has its own Unassigned and it is a waiting room
    /// rather than a customer. Moving one would merge two organizations'
    /// unfiled domains, which is the single thing this layer exists to stop.
    /// </summary>
    [Fact]
    public async Task WillNotMoveTheUnassignedBucket()
    {
        await SeedAsync("acme.example", "Acme Corp");
        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");

        Assert.Equal(ReportStore.MoveOutcome.NotMovable,
            await _store.MoveClientAsync(ReportStore.UnassignedClientSlug, "nrg"));
    }

    /// <summary>
    /// A refusal must leave the database exactly as it was. The move runs in
    /// one transaction precisely so a half-moved client cannot exist, and a
    /// half-moved client is worse than an unmoved one: its reports answer to
    /// neither organization.
    /// </summary>
    [Fact]
    public async Task ARefusedMoveChangesNothing()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");
        var from = await TenantIdAsync(ReportStore.DefaultTenantSlug);
        var before = await RowsInAsync("aggregate_records", from);

        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");
        await new ReportStore(_dbPath, "nrg").CreateClientAsync("Acme Corp");

        Assert.Equal(ReportStore.MoveOutcome.SlugTaken, await _store.MoveClientAsync(slug, "nrg", from));
        Assert.Equal(before, await RowsInAsync("aggregate_records", from));
    }

    /// <summary>
    /// The list of tables is spelled out so the SQL stays greppable, which
    /// means it can fall behind the schema. This recomputes it from the live
    /// database and fails when a new table appears that a move would leave
    /// behind - the same guard AssignDomainAsync already has.
    /// </summary>
    [Fact]
    public async Task EveryClientScopedTableIsHandled()
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        var tables = new List<string>();
        await using (var list = db.CreateCommand())
        {
            list.CommandText =
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
            await using var reader = await list.ExecuteReaderAsync();
            while (await reader.ReadAsync()) { tables.Add(reader.GetString(0)); }
        }

        var needBoth = new List<string>();
        foreach (var table in tables)
        {
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await using var info = db.CreateCommand();
            info.CommandText = $"PRAGMA table_info({table})";
            await using var reader = await info.ExecuteReaderAsync();
            while (await reader.ReadAsync()) { columns.Add(reader.GetString(1)); }

            if (columns.Contains("tenant_id") && columns.Contains("client_id")) { needBoth.Add(table); }
        }

        Assert.Equal(
            needBoth.OrderBy(t => t, StringComparer.Ordinal),
            ReportStore.ClientScopedTables.OrderBy(t => t, StringComparer.Ordinal));
    }

    /// <summary>
    /// A master can see every organization, so a slug alone may name two
    /// different customers. Guessing would move somebody else's.
    /// </summary>
    [Fact]
    public async Task RefusesToGuessWhenTwoOrganizationsHoldTheSameSlug()
    {
        var slug = await SeedAsync("acme.example", "Acme Corp");
        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");
        await _organizations.CreateAsync("NextLayerSec", slug: "nls");
        await new ReportStore(_dbPath, "nrg").CreateClientAsync("Acme Corp");

        Assert.Equal(ReportStore.MoveOutcome.Ambiguous, await _store.MoveClientAsync(slug, "nls"));

        // Named, it moves the right one.
        var from = await TenantIdAsync(ReportStore.DefaultTenantSlug);
        Assert.Equal(ReportStore.MoveOutcome.Moved, await _store.MoveClientAsync(slug, "nls", from));
    }

    /// <summary>
    /// The pre-existing bug this file turned up. The schema declares
    /// UNIQUE(tenant_id, slug) - per organization - and the create checked
    /// the whole table, so the first organization to file a customer as
    /// "acme-corp" silently stopped every other organization from having one.
    /// </summary>
    [Fact]
    public async Task TwoOrganizationsMayBothHaveAClientWithTheSameSlug()
    {
        await SeedAsync("acme.example", "Acme Corp");
        await _organizations.CreateAsync("NRG Tech Services", slug: "nrg");

        Assert.NotNull(await new ReportStore(_dbPath, "nrg").CreateClientAsync("Acme Corp"));
    }
}
