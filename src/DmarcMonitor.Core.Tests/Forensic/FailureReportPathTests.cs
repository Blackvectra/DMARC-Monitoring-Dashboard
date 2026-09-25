using System.Text;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Forensic;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Core.Tests.Forensic;

/// <summary>
/// A failure report from a file to a page, against the real schema.
///
/// The parser is tested on its own; this is about everything downstream of it,
/// which is where the table that had never been written to turns out to be
/// missing things. It also holds the two rules that are properties of the
/// stored row rather than of the parse: importing the same mailbox twice does
/// not duplicate somebody's mail, and the body of the reported message is not
/// in the database.
/// </summary>
public sealed class FailureReportPathTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-ruf-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public FailureReportPathTests()
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

    /// <summary>A failure report as a receiver sends one, about the given domain.</summary>
    private static string Report(
        string domain = "ndaco.org", string subject = "Updated remittance details",
        string delivery = "reject", string ip = "203.0.113.44") => $"""
        From: dmarc-reports@receiver.example
        To: dmarc@nrgtechservices.com
        Subject: Auth Failure Report
        MIME-Version: 1.0
        Content-Type: multipart/report; report-type=feedback-report; boundary="b1"

        --b1
        Content-Type: text/plain

        An authentication failure report.

        --b1
        Content-Type: message/feedback-report

        Feedback-Type: auth-failure
        User-Agent: Receiver-Feedback/1.0
        Version: 1
        Original-Mail-From: <billing@{domain}>
        Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000
        Source-IP: {ip}
        Reported-Domain: {domain}
        Auth-Failure: dmarc
        Delivery-Result: {delivery}
        Authentication-Results: mx.receiver.example; dkim=fail header.d={domain}; spf=fail

        --b1
        Content-Type: message/rfc822

        From: "Accounts Payable" <billing@{domain}>
        To: accounts@example.net
        Subject: {subject}
        Message-ID: <{Guid.NewGuid():N}@{domain}>
        Date: Tue, 15 Sep 2026 09:12:00 +0000

        Please update our bank details before the next payment run.
        --b1--
        """;

    private static ImportFile File_(string name, string content) =>
        new(name, Encoding.UTF8.GetBytes(content));

    private static async IAsyncEnumerable<ImportFile> Files(params ImportFile[] files)
    {
        foreach (var file in files) { yield return file; await Task.Yield(); }
    }

    [Fact]
    public void AFailureReportIsRecognizedForWhatItIs()
    {
        Assert.Equal(ReportKind.DmarcFailure, ReportAttachment.Classify(Report()));
    }

    /// <summary>
    /// The classifier looks at the first meaningful character to tell XML from
    /// JSON, and a failure report begins with neither - which is exactly why
    /// these were Unknown until now. The other two must still be read.
    /// </summary>
    [Fact]
    public void TheOtherTwoReportTypesAreStillRecognized()
    {
        Assert.Equal(
            ReportKind.DmarcAggregate,
            ReportAttachment.Classify("<?xml version=\"1.0\"?><feedback><report_metadata/></feedback>"));

        Assert.Equal(
            ReportKind.TlsRpt,
            ReportAttachment.Classify("""{"organization-name":"x","policies":[]}"""));
    }

    [Fact]
    public async Task ImportsAFailureReportAndFilesItUnderItsDomain()
    {
        var result = await new ReportImporter(_store).ImportAsync(Files(File_("report.eml", Report())));

        Assert.Equal(1, result.Stored);
        Assert.Empty(result.Errors);

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM forensic_reports"));
        Assert.Equal("ndaco.org", await TextAsync(
            "SELECT d.name FROM forensic_reports f JOIN domains d ON d.id = f.domain_id"));
        Assert.Equal("203.0.113.44", await TextAsync("SELECT source_ip FROM forensic_reports"));
        Assert.Equal("reject", await TextAsync("SELECT delivery_result FROM forensic_reports"));
        Assert.Equal("Receiver-Feedback/1.0", await TextAsync("SELECT reported_by FROM forensic_reports"));
    }

    /// <summary>
    /// Pointing the importer at the same mailbox again is the commonest thing
    /// an operator does, and without a hash it would leave a second copy of
    /// every reported message - each with its own thirty days.
    /// </summary>
    [Fact]
    public async Task ImportingTheSameReportTwiceStoresItOnce()
    {
        var report = Report();
        var importer = new ReportImporter(_store);

        Assert.Equal(1, (await importer.ImportAsync(Files(File_("a.eml", report)))).Stored);

        var again = await importer.ImportAsync(Files(File_("a-copy.eml", report)));
        Assert.Equal(0, again.Stored);
        Assert.Equal(1, again.AlreadyStored);

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM forensic_reports"));
    }

    /// <summary>
    /// The rule that matters most, asserted where it can actually be broken:
    /// against the database, after everything in between has run.
    /// </summary>
    [Fact]
    public async Task TheBodyOfTheReportedMessageIsNotInTheDatabase()
    {
        await new ReportImporter(_store).ImportAsync(Files(File_("report.eml", Report())));

        var headers = await TextAsync("SELECT raw_headers FROM forensic_reports");

        Assert.Contains("Subject: Updated remittance details", headers, StringComparison.Ordinal);
        Assert.DoesNotContain("bank details", headers, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two customers' reports do not become one customer's.
    /// </summary>
    /// <remarks>
    /// The usual multi-tenant rule, and it bites harder here than anywhere
    /// else in the product: every other table leaking across a boundary is a
    /// wrong count, and this one is a subject line.
    /// </remarks>
    [Fact]
    public async Task ReportsAreFiledUnderTheDomainTheyNameAndNoOther()
    {
        await new ReportImporter(_store).ImportAsync(Files(
            File_("a.eml", Report("ndaco.org", "One")),
            File_("b.eml", Report("dmvwrr.com", "Two"))));

        var service = new ForensicReportService(_dbPath);

        var all = await service.ListAsync(days: 3650);
        Assert.Equal(2, all.Count);

        var one = await service.ListAsync(days: 3650, domain: "ndaco.org");
        Assert.Single(one);
        Assert.Equal("One", one[0].Subject);
    }

    [Fact]
    public async Task TheServiceSummarizesWhatArrivedWithoutReadingAnyOfIt()
    {
        await new ReportImporter(_store).ImportAsync(Files(
            File_("a.eml", Report("ndaco.org", "One", delivery: "reject")),
            File_("b.eml", Report("ndaco.org", "Two", delivery: "none")),
            File_("c.eml", Report("dmvwrr.com", "Three", delivery: "delivered"))));

        var summary = await new ForensicReportService(_dbPath).SummarizeAsync(days: 3650);

        Assert.Equal(3, summary.Total);
        Assert.Equal(2, summary.Domains);

        // Two of the three reached somebody, which is the number this page
        // exists to put in front of an operator.
        Assert.Equal(2, summary.Delivered);
        Assert.Equal(["Receiver-Feedback/1.0"], summary.Reporters);
    }

    /// <summary>
    /// Headers are fetched by a separate call, scoped like everything else, so
    /// a page that shows a list cannot accidentally hand out the contents.
    /// </summary>
    [Fact]
    public async Task HeadersAreASecondCallAndAreScoped()
    {
        await new ReportImporter(_store).ImportAsync(Files(File_("a.eml", Report())));

        var service = new ForensicReportService(_dbPath);
        var row = (await service.ListAsync(days: 3650))[0];

        Assert.Contains(
            "Updated remittance details",
            await service.HeadersAsync(row.Id) ?? "",
            StringComparison.Ordinal);

        // Another organization asking for the same row gets nothing.
        Assert.Null(await service.HeadersAsync(row.Id, tenantId: "some-other-organization"));
    }

    /// <summary>
    /// Retention for these is separate and shorter, and the enforcement is
    /// what makes that more than a comment in the schema.
    /// </summary>
    [Fact]
    public async Task OldFailureReportsArePrunedOnTheirOwnShorterClock()
    {
        await new ReportImporter(_store).ImportAsync(Files(File_("a.eml", Report())));

        // Older than the forensic window and well inside the aggregate one,
        // which is the whole point of the two being different numbers.
        var policy = new RetentionPolicy();
        await ExecuteAsync(
            "UPDATE forensic_reports SET received_at = "
          + $"'{DateTimeOffset.UtcNow.AddDays(-policy.ForensicDays - 1).UtcDateTime:yyyy-MM-dd HH:mm:ss}'");

        var pruned = await new RetentionService(_dbPath).ApplyAsync(policy, DateTimeOffset.UtcNow, "tests");

        Assert.Equal(1, pruned.ForensicReports);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM forensic_reports"));
    }

    /// <summary>
    /// A domain that reports have arrived for is a domain the importer creates,
    /// exactly as an aggregate report would - so a failure report for a client
    /// nobody has onboarded is kept rather than refused.
    /// </summary>
    [Fact]
    public async Task AReportForAnUnknownDomainStillLands()
    {
        var result = await new ReportImporter(_store)
            .ImportAsync(Files(File_("a.eml", Report("nobody-has-onboarded-this.example"))));

        Assert.Equal(1, result.Stored);
        Assert.Equal(
            "nobody-has-onboarded-this.example",
            await TextAsync("SELECT d.name FROM forensic_reports f JOIN domains d ON d.id = f.domain_id"));
    }

    /// <summary>
    /// An abuse report arriving at the same mailbox is refused with a reason
    /// rather than filed as an authentication failure against the domain.
    /// </summary>
    [Fact]
    public async Task AnAbuseReportIsNotStoredAsAFailure()
    {
        var result = await new ReportImporter(_store).ImportAsync(Files(File_("spam.eml", """
            Content-Type: multipart/report; report-type=feedback-report; boundary="b1"

            --b1
            Content-Type: message/feedback-report

            Feedback-Type: abuse
            User-Agent: SomeISP/1.0
            Version: 1
            Reported-Domain: ndaco.org

            --b1--
            """)));

        Assert.Equal(0, result.Stored);
        Assert.Equal(1, result.Failed);
        Assert.Contains(result.Errors, e => e.Contains("'abuse'", StringComparison.Ordinal));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM forensic_reports"));
    }

    /// <summary>
    /// Aggregate reports still import beside them, because the classifier now
    /// has a branch it did not have and the ordering of those checks decides
    /// whether every other report type keeps working.
    /// </summary>
    [Fact]
    public async Task AggregateReportsStillImportAlongside()
    {
        var xml = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "google-aggregate.xml"));

        var result = await new ReportImporter(_store).ImportAsync(Files(
            File_("agg.xml", xml),
            File_("ruf.eml", Report())));

        Assert.Equal(2, result.Stored);
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM aggregate_reports"));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM forensic_reports"));
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> CountAsync(string sql) =>
        Convert.ToInt64(await RawAsync(sql), System.Globalization.CultureInfo.InvariantCulture);

    private async Task<string> TextAsync(string sql) => await RawAsync(sql) as string ?? "";

    private async Task<object?> RawAsync(string sql)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }
}
