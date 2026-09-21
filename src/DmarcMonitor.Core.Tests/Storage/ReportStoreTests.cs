using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Storing reports in SQLite, against the real schema and the real reports.
///
/// Each test gets its own database file, so nothing depends on the order they
/// run in.
/// </summary>
public sealed class ReportStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-test-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public ReportStoreTests()
    {
        _store = new ReportStore(_dbPath);
        var schema = File.ReadAllText(FindSchema());
        _store.InitializeAsync(schema).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
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

    private static AggregateReport Aggregate(string fixture) =>
        AggregateReportParser.Parse(Fixture(fixture)).Report!;

    private static TlsReport Tls(string fixture) =>
        TlsReportParser.Parse(Fixture(fixture)).Report!;

    [Fact]
    public async Task CreatesADatabaseWithTheExpectedTables()
    {
        Assert.True(await _store.IsInitializedAsync());
    }

    [Fact]
    public async Task StoresARealAggregateReport()
    {
        var report = Aggregate("google-aggregate.xml");
        var id = await _store.SaveAggregateAsync(report, Fixture("google-aggregate.xml"), "msg-1");

        Assert.NotNull(id);
        Assert.True(await _store.IsAggregateStoredAsync(
            report.Metadata.OrgName, report.Metadata.ReportId, report.Policy.Domain));
    }

    [Fact]
    public async Task StoresEveryRecordOfALargeReport()
    {
        // The Outlook report has 123 records. Storing the header and losing
        // the rows would leave a report that exists and says nothing.
        var report = Aggregate("outlook-aggregate.xml");
        Assert.NotNull(await _store.SaveAggregateAsync(report, "raw", "msg-1"));

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*), SUM(message_count) FROM aggregate_records";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.Equal(123, reader.GetInt32(0));
        Assert.Equal(report.TotalMessages, reader.GetInt64(1));
    }

    [Fact]
    public async Task RefusesToStoreTheSameReportTwice()
    {
        // The database is the last line of defense behind the ingestor's own
        // check: a crash between the two must not inflate a customer's volume
        // when the message is read again.
        var report = Aggregate("google-aggregate.xml");

        Assert.NotNull(await _store.SaveAggregateAsync(report, "raw", "msg-1"));
        Assert.Null(await _store.SaveAggregateAsync(report, "raw", "msg-1"));
    }

    [Fact]
    public async Task LeavesNoPartialRowsBehindWhenItRefusesADuplicate()
    {
        // A rolled-back duplicate that left its records behind would double
        // the message count while the report count stayed right, which is
        // the hardest kind of wrong number to notice.
        var report = Aggregate("outlook-aggregate.xml");
        await _store.SaveAggregateAsync(report, "raw", "msg-1");
        await _store.SaveAggregateAsync(report, "raw", "msg-2");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM aggregate_records";
        Assert.Equal(123L, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task StoresTwoReportsFromDifferentReceiversForTheSameDomain()
    {
        // Report ids are unique per reporter, not globally. Rejecting the
        // second would discard a whole receiver's view.
        Assert.NotNull(await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw"));
        Assert.NotNull(await _store.SaveAggregateAsync(Aggregate("gosecure-aggregate.xml"), "raw"));
    }

    [Fact]
    public async Task StoresARealTlsReport()
    {
        var report = Tls("google-tlsrpt.json");
        Assert.NotNull(await _store.SaveTlsAsync(report, Fixture("google-tlsrpt.json"), "msg-1"));
        Assert.True(await _store.IsTlsStoredAsync(report.OrganizationName, report.ReportId, "nrgtechservices.com"));
    }

    [Fact]
    public async Task RecordsTheMtaStsModeThatWasInForce()
    {
        // The whole reason for the schema change. Without this column, a
        // domain in testing mode is indistinguishable from one enforcing, and
        // every report looks like success.
        await _store.SaveTlsAsync(Tls("google-tlsrpt.json"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_mode FROM tls_reports LIMIT 1";
        Assert.Equal("testing", (string?)await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task StoresTlsReportsFromTwoReceiversForTheSameDomain()
    {
        Assert.NotNull(await _store.SaveTlsAsync(Tls("google-tlsrpt.json"), "raw"));
        Assert.NotNull(await _store.SaveTlsAsync(Tls("microsoft-tlsrpt.json"), "raw"));
    }

    [Fact]
    public async Task FilesANewDomainUnderUnassignedRatherThanRejectingIt()
    {
        // Reports arrive for domains before anybody onboards them. Discarding
        // those loses data that cannot be recovered afterwards.
        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw");

        var unassigned = await _store.GetUnassignedDomainsAsync();
        Assert.Contains("nrgtechservices.com", unassigned);
    }

    [Fact]
    public async Task ReusesTheSameDomainRowForEveryReport()
    {
        // A second domain row would split one customer's data in two, and
        // every total would silently be half right.
        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw");
        await _store.SaveAggregateAsync(Aggregate("gosecure-aggregate.xml"), "raw");
        await _store.SaveTlsAsync(Tls("google-tlsrpt.json"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM domains WHERE name = 'nrgtechservices.com'";
        Assert.Equal(1L, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task RecordsThePolicyThatWasLiveAtTheTime()
    {
        // Historical value: this is how you prove to a customer what their
        // policy was on a given date, after it has since changed.
        await _store.SaveAggregateAsync(Aggregate("gosecure-aggregate.xml"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_p, policy_adkim, policy_aspf FROM aggregate_reports LIMIT 1";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.Equal("reject", reader.GetString(0));
        Assert.Equal("s", reader.GetString(1));
        Assert.Equal("s", reader.GetString(2));
    }

    [Fact]
    public async Task MarksIpv6SourcesCorrectly()
    {
        // The schema constrains this to 4 or 6, so getting it wrong is not a
        // cosmetic problem: the insert fails and the report is lost.
        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM aggregate_records WHERE source_ip_version = 6";
        Assert.True(Convert.ToInt64(await command.ExecuteScalarAsync()) > 0);
    }

    [Fact]
    public async Task ReportsNothingStoredForAReportItHasNotSeen()
    {
        Assert.False(await _store.IsAggregateStoredAsync("google.com", "never-seen", "nrgtechservices.com"));
        Assert.False(await _store.IsTlsStoredAsync("Google Inc.", "never-seen", "nrgtechservices.com"));
    }

    [Fact]
    public async Task ReportsNoUnassignedDomainsForAnEmptyDatabase()
    {
        Assert.Empty(await _store.GetUnassignedDomainsAsync());
    }

    [Fact]
    public async Task KeepsTheAuthResultAlongsideTheDomainItWasFor()
    {
        // The bug real data found. 35.174.145.124 attempts a DKIM signature AS
        // dmvwrr.com with selector1, and it FAILS: a forgery attempt. Storing
        // only the domain made that indistinguishable from dmvwrr.com's own
        // misconfigured service, so the correlation view would have told an
        // operator to go and fix a sender that was never theirs.
        await _store.SaveAggregateAsync(Aggregate("dmv-entoutlook-aggregate.xml"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT dkim_domain, dkim_auth_result
            FROM aggregate_records
            WHERE source_ip = '35.174.145.124' AND dkim_domain IS NOT NULL
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), "the forged-signature record should be stored");

        Assert.Equal("dmvwrr.com", reader.GetString(0));
        Assert.Equal("fail", reader.GetString(1));
    }

    [Fact]
    public async Task StoresAPassingAuthResultInPreferenceToAFailingOne()
    {
        // gosecure.net sends three SPF results for one message: two passing
        // for other domains and one failing for this one. Taking the first
        // would record the failure and lose the fact that anything passed.
        await _store.SaveAggregateAsync(Aggregate("gosecure-aggregate.xml"), "raw");

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT spf_domain, spf_auth_result FROM aggregate_records LIMIT 1";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.Equal("pass", reader.GetString(1));
        Assert.NotEqual("nrgtechservices.com", reader.GetString(0));   // the failing one
    }

    [Fact]
    public void RejectsAnEmptyDatabasePath()
    {
        Assert.Throws<ArgumentException>(() => new ReportStore("  "));
    }
}
