using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Onboarding a domain: moving it off Unassigned and onto a real client.
///
/// The interesting part is not the domains row, it is everything filed against
/// it. Reports already stored carry a denormalized client_id, so an assignment
/// that updates only the domain leaves the history behind and the new client's
/// report comes back empty — which reads as a domain that has never sent mail
/// rather than as a broken assignment.
/// </summary>
public sealed class ReportStoreAssignmentTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-assign-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public ReportStoreAssignmentTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(File.ReadAllText(FindSchema())).GetAwaiter().GetResult();
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    private static string FindSchema()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "db", "schema.sql");
            if (File.Exists(candidate)) { return candidate; }
        }
        throw new FileNotFoundException("Could not find db/schema.sql from the test output directory.");
    }

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    /// <summary>Stores a real report, so there is history to move.</summary>
    private async Task<AggregateReport> StoreAsync(string fixture)
    {
        var report = AggregateReportParser.Parse(Fixture(fixture)).Report!;
        await _store.SaveAggregateAsync(report, Fixture(fixture), null);
        return report;
    }

    /// <summary>
    /// Whose file holds the domain's records - and the client every one of them
    /// says it belongs to, which must be the same client.
    /// </summary>
    private async Task<string> ClientOfRecordsAsync(string domain)
    {
        var files = new ClientDatabases(_dbPath);
        var holders = new List<string>();

        foreach (var client in await files.ListAsync())
        {
            if (!File.Exists(files.PathFor(client))) { continue; }

            await using var connection = await files.OpenAsync(ClientScope.Client(client.Id));
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT DISTINCT c.slug
                FROM aggregate_records r
                JOIN clients c ON c.id = r.client_id
                JOIN domains d ON d.id = r.domain_id
                WHERE d.name = $name
                """;
            command.Parameters.AddWithValue("$name", domain);

            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                // A row in one client's file saying it is another's is the
                // move half done.
                Assert.Equal(client.Slug, reader.GetString(0));
                holders.Add(client.Slug);
            }
        }

        // More than one means the history was split across clients, which is
        // worse than not moving it at all.
        return Assert.Single(holders);
    }

    // ---- the case that matters ---------------------------------------------

    [Fact]
    public async Task AssigningADomainMovesTheReportsAlreadyStoredForIt()
    {
        var report = await StoreAsync("google-aggregate.xml");
        Assert.Equal(ReportStore.UnassignedClientSlug, await ClientOfRecordsAsync(report.Policy.Domain));

        var slug = await _store.CreateClientAsync("NRG Tech Services");
        Assert.Equal(ReportStore.AssignOutcome.Assigned,
            await _store.AssignDomainAsync(report.Policy.Domain, slug!));

        Assert.Equal(slug, await ClientOfRecordsAsync(report.Policy.Domain));
    }

    [Fact]
    public async Task ReportsArrivingAfterAssignmentGoToTheSameClient()
    {
        // EnsureDomain keeps an existing domain's client, so onboarding must
        // not be undone by the next night's report.
        var report = await StoreAsync("google-aggregate.xml");
        var slug = await _store.CreateClientAsync("NRG Tech Services");
        await _store.AssignDomainAsync(report.Policy.Domain, slug!);

        // Same domain, a different receiver: what tomorrow's ingest looks like.
        await StoreAsync("outlook-aggregate.xml");

        Assert.Equal(slug, await ClientOfRecordsAsync(report.Policy.Domain));
    }

    [Fact]
    public async Task EveryTableThatCarriesBothIdsIsHandled()
    {
        // The guard. A table added later with a denormalized client_id and a
        // domain_id would silently keep pointing at the old client, and the
        // symptom - a client report missing a section - would look like a
        // reporting bug rather than an assignment one.

        // In the organization's database: updated in place.
        await using (var registry = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            await registry.OpenAsync();
            var needBoth = new List<string>();
            foreach (var table in await TablesAsync(registry))
            {
                var columns = await ColumnsAsync(registry, table);
                if (columns.Contains("client_id") && columns.Contains("domain_id")) { needBoth.Add(table); }
            }

            Assert.Equal(
                needBoth.OrderBy(t => t, StringComparer.Ordinal),
                ReportStore.RegistryDomainTables.OrderBy(t => t, StringComparer.Ordinal));
        }

        // In a client's file: moved to the new client's. Everything with a
        // domain_id, and whatever hangs off one of those by a key that deletes
        // with it - a TLS report's failure details have no domain of their own.
        await using var file = new SqliteConnection("Data Source=:memory:;Pooling=False");
        await file.OpenAsync();
        await using (var create = file.CreateCommand())
        {
            create.CommandText = DatabaseSchema.ClientSql;
            await create.ExecuteNonQueryAsync();
        }

        var moves = new HashSet<string>(StringComparer.Ordinal);
        var tables = await TablesAsync(file);
        foreach (var table in tables)
        {
            if ((await ColumnsAsync(file, table)).Contains("domain_id")) { moves.Add(table); }
        }

        for (var added = true; added;)
        {
            added = false;
            foreach (var table in tables.Where(t => !moves.Contains(t)))
            {
                await using var keys = file.CreateCommand();
                keys.CommandText = $"SELECT \"table\", on_delete FROM pragma_foreign_key_list('{table}')";
                await using var reader = await keys.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    if (moves.Contains(reader.GetString(0)) && reader.GetString(1) == "CASCADE")
                    {
                        added |= moves.Add(table);
                    }
                }
            }
        }

        Assert.Equal(
            moves.OrderBy(t => t, StringComparer.Ordinal),
            ReportStore.DomainScopedTables.OrderBy(t => t, StringComparer.Ordinal));

        // And in the order a move needs: a row's parent is in place before it.
        Assert.True(
            ReportStore.DomainScopedTables.ToList().IndexOf("tls_reports")
                < ReportStore.DomainScopedTables.ToList().IndexOf("tls_failure_details"));
        Assert.True(
            ReportStore.DomainScopedTables.ToList().IndexOf("aggregate_reports")
                < ReportStore.DomainScopedTables.ToList().IndexOf("aggregate_records"));
        Assert.True(
            ReportStore.DomainScopedTables.ToList().IndexOf("dns_change_plans")
                < ReportStore.DomainScopedTables.ToList().IndexOf("dns_changes"));
    }

    private static async Task<List<string>> TablesAsync(SqliteConnection db)
    {
        var tables = new List<string>();
        await using var list = db.CreateCommand();
        list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
        await using var reader = await list.ExecuteReaderAsync();
        while (await reader.ReadAsync()) { tables.Add(reader.GetString(0)); }
        return tables;
    }

    private static async Task<HashSet<string>> ColumnsAsync(SqliteConnection db, string table)
    {
        var columns = new HashSet<string>(StringComparer.Ordinal);
        await using var info = db.CreateCommand();
        info.CommandText = $"SELECT name FROM pragma_table_info('{table}')";
        await using var reader = await info.ExecuteReaderAsync();
        while (await reader.ReadAsync()) { columns.Add(reader.GetString(0)); }
        return columns;
    }

    // ---- refusals ------------------------------------------------------------

    [Fact]
    public async Task RefusesADomainNobodyHasReportedFor()
    {
        var slug = await _store.CreateClientAsync("NRG Tech Services");

        Assert.Equal(ReportStore.AssignOutcome.DomainNotFound,
            await _store.AssignDomainAsync("never-seen.example", slug!));
    }

    [Fact]
    public async Task RefusesAClientThatDoesNotExist()
    {
        var report = await StoreAsync("google-aggregate.xml");

        Assert.Equal(ReportStore.AssignOutcome.ClientNotFound,
            await _store.AssignDomainAsync(report.Policy.Domain, "no-such-client"));
    }

    [Fact]
    public async Task SaysSoRatherThanPretendingToWorkTwice()
    {
        var report = await StoreAsync("google-aggregate.xml");
        var slug = await _store.CreateClientAsync("NRG Tech Services");
        await _store.AssignDomainAsync(report.Policy.Domain, slug!);

        Assert.Equal(ReportStore.AssignOutcome.AlreadyAssigned,
            await _store.AssignDomainAsync(report.Policy.Domain, slug!));
    }

    [Fact]
    public async Task MatchesTheDomainWithoutCareForCaseOrATrailingDot()
    {
        // Receivers are inconsistent about both, and so are operators typing
        // a domain in from a report.
        var report = await StoreAsync("google-aggregate.xml");
        var slug = await _store.CreateClientAsync("NRG Tech Services");

        Assert.Equal(ReportStore.AssignOutcome.Assigned,
            await _store.AssignDomainAsync(report.Policy.Domain.ToUpperInvariant() + ".", slug!));
    }

    // ---- clients -------------------------------------------------------------

    [Fact]
    public async Task RefusesASecondClientWithTheSameSlug()
    {
        Assert.NotNull(await _store.CreateClientAsync("Morton, ND"));
        Assert.Null(await _store.CreateClientAsync("morton nd"));
    }

    [Fact]
    public async Task ListsUnassignedAlongsideTheRest()
    {
        var report = await StoreAsync("google-aggregate.xml");
        await _store.CreateClientAsync("NRG Tech Services");

        var clients = await _store.GetClientsAsync();

        Assert.Contains(clients, c => c.Slug == ReportStore.UnassignedClientSlug && c.Domains == 1);
        Assert.Contains(clients, c => c.Slug == "nrg-tech-services" && c.Domains == 0);
        Assert.Contains(clients, c => c.Slug == ReportStore.UnassignedClientSlug && c.Messages > 0);
        Assert.NotEqual("", report.Policy.Domain);
    }

    [Fact]
    public async Task CountsMessagesAgainstTheClientTheDomainMovedTo()
    {
        var report = await StoreAsync("google-aggregate.xml");
        var slug = await _store.CreateClientAsync("NRG Tech Services");
        await _store.AssignDomainAsync(report.Policy.Domain, slug!);

        var clients = await _store.GetClientsAsync();

        Assert.Equal(0, clients.Single(c => c.Slug == ReportStore.UnassignedClientSlug).Messages);
        Assert.True(clients.Single(c => c.Slug == slug).Messages > 0);
    }

    [Theory]
    [InlineData("Morton, ND", "morton-nd")]
    [InlineData("  Acme  Corp  ", "acme-corp")]
    [InlineData("O'Brien & Sons", "o-brien-sons")]
    [InlineData("---", "")]
    // Accents are folded, not dropped. Scandinavian and German surnames are
    // ordinary in North Dakota, and "Søren Ågård Farms" used to become
    // "s-ren-g-rd-farms" - in a filename nobody can change afterwards.
    [InlineData("Søren Ågård Farms", "soren-agard-farms")]
    [InlineData("Hügel Bräu", "hugel-brau")]
    [InlineData("Åse Ødegård", "ase-odegard")]
    [InlineData("Weiß & Söhne", "weiss-sohne")]
    [InlineData("José Peña", "jose-pena")]
    // Nothing to build from is still nothing: the page says so rather than
    // inventing a name.
    [InlineData("客户公司", "")]
    public void SlugifyProducesSomethingUsableInAFilename(string input, string expected) =>
        Assert.Equal(expected, ReportStore.Slugify(input));

    [Fact]
    public void ASlugIsShortEnoughToBeAFilename()
    {
        // A client report is this plus a month plus an extension, and a
        // filesystem stops at 255 bytes. Cut at a word, so it still reads.
        var slug = ReportStore.Slugify(string.Join(" ", Enumerable.Repeat("Prairie", 40)));

        Assert.True(slug.Length <= 60, $"slug was {slug.Length} characters");
        Assert.DoesNotContain("--", slug, StringComparison.Ordinal);
        Assert.False(slug.EndsWith('-'));
        Assert.StartsWith("prairie-prairie", slug, StringComparison.Ordinal);
    }
}
