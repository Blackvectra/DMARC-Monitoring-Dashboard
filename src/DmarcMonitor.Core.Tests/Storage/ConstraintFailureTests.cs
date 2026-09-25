using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// The difference between "the database already holds this report" and "the
/// database refused this report".
///
/// Both arrive as SQLITE_CONSTRAINT - error code 19 - and the store treated
/// the whole family as the first one. NOT NULL, FOREIGN KEY, CHECK and UNIQUE
/// were all reported to the operator as "already stored".
///
/// Found against real data, and it had already cost something: migration 0013
/// made received_at nullable, `dmarc import` writes NULL there because a file
/// on disk has no arrival time, and against a database still at 0012 every
/// insert hit NOT NULL. The command read 404 files, stored none, printed "404
/// already stored" and exited 0. Sixty-five of those reports were new.
///
/// So the rule is narrow on purpose: only a uniqueness violation is a
/// duplicate. Anything else is a fault, and a report that could not be stored
/// has to reach the person who ran the command, because it is data lost.
/// </summary>
public sealed class ConstraintFailureTests
{
    private const string Xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>google.com</org_name>
            <email>noreply-dmarc@google.com</email>
            <report_id>test-report-0001</report_id>
            <date_range><begin>1789948800</begin><end>1790035199</end></date_range>
          </report_metadata>
          <policy_published>
            <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
            <p>quarantine</p><sp>quarantine</sp><pct>100</pct>
          </policy_published>
          <record>
            <row>
              <source_ip>203.0.113.10</source_ip><count>5</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
            </row>
            <identifiers><header_from>example.com</header_from></identifiers>
            <auth_results>
              <dkim><domain>example.com</domain><result>pass</result></dkim>
              <spf><domain>example.com</domain><result>pass</result></spf>
            </auth_results>
          </record>
        </feedback>
        """;

    /// <summary>The behaviour that must be kept: a genuine duplicate is not an error.</summary>
    [Fact]
    public async Task TheSameReportTwiceIsStoredOnceAndNotAnError()
    {
        using var db = new TempDatabase();
        var store = new ReportStore(db.Path);
        var report = Parse();

        var first = await store.SaveAggregateAsync(report, Xml);
        var second = await store.SaveAggregateAsync(report, Xml);

        Assert.NotNull(first);
        Assert.Null(second);   // null means "already stored", and only that
    }

    /// <summary>
    /// A constraint failure that is NOT about uniqueness must reach the
    /// caller. A trigger raising ABORT is the cheapest way to produce one
    /// deterministically - it arrives as SQLITE_CONSTRAINT_TRIGGER, which is
    /// error code 19 and extended code 1811, exactly the shape a NOT NULL
    /// violation against an unmigrated database has.
    /// </summary>
    [Fact]
    public async Task AConstraintFailureThatIsNotADuplicateIsNotReportedAsOne()
    {
        using var db = new TempDatabase();
        var store = new ReportStore(db.Path);

        // A first report, so the client file the next one goes into exists
        // to put the trigger in: a client's reports are in its own file.
        var warmUp = Xml.Replace("test-report-0001", "test-report-0000", StringComparison.Ordinal);
        Assert.NotNull(await store.SaveAggregateAsync(AggregateReportParser.Parse(warmUp).Report!, warmUp));

        var file = Assert.Single(Directory.GetFiles(ClientDatabases.FolderFor(db.Path), "*.db"));

        await using (var connection = new SqliteConnection($"Data Source={file};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TRIGGER refuse_every_report BEFORE INSERT ON aggregate_reports
                BEGIN SELECT RAISE(ABORT, 'this database will not take it'); END;
                """;
            await command.ExecuteNonQueryAsync();
        }

        var ex = await Assert.ThrowsAsync<SqliteException>(
            () => store.SaveAggregateAsync(Parse(), Xml));

        // The exact shape the old code mistook for a duplicate.
        Assert.Equal(19, ex.SqliteErrorCode);
        Assert.NotEqual(2067, ex.SqliteExtendedErrorCode);   // not SQLITE_CONSTRAINT_UNIQUE

        // And nothing was left behind by the attempt: the warm-up is all there is.
        await using var check = new SqliteConnection($"Data Source={file};Pooling=False");
        await check.OpenAsync();
        await using var count = check.CreateCommand();
        count.CommandText = "SELECT count(*) FROM aggregate_reports;";
        Assert.Equal(1L, (long)(await count.ExecuteScalarAsync())!);
    }

    private static AggregateReport Parse()
    {
        var parsed = AggregateReportParser.Parse(Xml);
        Assert.True(parsed.Success, parsed.Error);
        return parsed.Report!;
    }

    private sealed class TempDatabase : IDisposable
    {
        private readonly string _dir;

        public TempDatabase()
        {
            _dir = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"dmarc-constraint-{Guid.NewGuid():N}");
            Directory.CreateDirectory(_dir);
            Path = System.IO.Path.Combine(_dir, "dmarc.db");
            new ReportStore(Path).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        }

        public string Path { get; }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            try { Directory.Delete(_dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
