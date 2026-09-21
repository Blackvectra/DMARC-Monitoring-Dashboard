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

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

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

    private async Task<string> ClientOfRecordsAsync(string domain)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT DISTINCT c.slug
            FROM aggregate_records r
            JOIN clients c ON c.id = r.client_id
            JOIN domains d ON d.id = r.domain_id
            WHERE d.name = $name
            """;
        command.Parameters.AddWithValue("$name", domain);

        var slugs = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) { slugs.Add(reader.GetString(0)); }

        // More than one means the history was split across clients, which is
        // worse than not moving it at all.
        return Assert.Single(slugs);
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
        // symptom — a client report missing a section — would look like a
        // reporting bug rather than an assignment one.
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        await connection.OpenAsync();

        var tables = new List<string>();
        await using (var list = connection.CreateCommand())
        {
            list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name";
            await using var reader = await list.ExecuteReaderAsync();
            while (await reader.ReadAsync()) { tables.Add(reader.GetString(0)); }
        }

        var needBoth = new List<string>();
        foreach (var table in tables)
        {
            var columns = new HashSet<string>(StringComparer.Ordinal);
            await using var info = connection.CreateCommand();
            info.CommandText = $"PRAGMA table_info({table})";
            await using var reader = await info.ExecuteReaderAsync();
            while (await reader.ReadAsync()) { columns.Add(reader.GetString(1)); }

            if (columns.Contains("client_id") && columns.Contains("domain_id")) { needBoth.Add(table); }
        }

        Assert.Equal(
            needBoth.OrderBy(t => t, StringComparer.Ordinal),
            ReportStore.DomainScopedTables.OrderBy(t => t, StringComparer.Ordinal));
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
