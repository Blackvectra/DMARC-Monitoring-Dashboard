using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Rollout;
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
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

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT spf_domain, spf_auth_result FROM aggregate_records LIMIT 1";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.Equal("pass", reader.GetString(1));
        Assert.NotEqual("nrgtechservices.com", reader.GetString(0));   // the failing one
    }

    // ---- which of several auth results a record is filed under ----
    //
    // A record can carry several DKIM results, and the columns hold one. A
    // Google Workspace message is signed twice - by google.com and by the
    // domain's own key - and both verify, but only the domain's own signature
    // is the one DMARC counts. Filed under the first, a row said its pass
    // rested on a signer that does not align with the From domain, and every
    // reader of the column was told something the receiver had not said.

    /// <summary>
    /// A report of one record for example.com, carrying the given auth_results.
    /// </summary>
    private static AggregateReport OneRecord(string authResults, string headerFrom = "example.com", string dkimVerdict = "pass")
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds();
        var xml = $"""
            <feedback>
              <report_metadata>
                <org_name>reporter.example.net</org_name><report_id>signers-1</report_id>
                <date_range><begin>{begin}</begin><end>{begin + 86399}</end></date_range>
              </report_metadata>
              <policy_published><domain>example.com</domain><p>none</p></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.10</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>{dkimVerdict}</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>{headerFrom}</header_from></identifiers>
                <auth_results>{authResults}</auth_results>
              </record>
            </feedback>
            """;
        return AggregateReportParser.Parse(xml).Report!;
    }

    private static string DkimResult(string domain, string selector, string result = "pass") =>
        $"<dkim><domain>{domain}</domain><selector>{selector}</selector><result>{result}</result></dkim>";

    private static string SpfResult(string domain, string scope, string result = "pass") =>
        $"<spf><domain>{domain}</domain><scope>{scope}</scope><result>{result}</result></spf>";

    private async Task<(string? Domain, string? Selector, string? Result)> StoredDkimAsync()
    {
        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT dkim_domain, dkim_selector, dkim_auth_result FROM aggregate_records";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        return (
            reader.IsDBNull(0) ? null : reader.GetString(0),
            reader.IsDBNull(1) ? null : reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2));
    }

    private async Task<(string? Domain, string? Result)> StoredSpfAsync()
    {
        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT spf_domain, spf_auth_result FROM aggregate_records";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        return (reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1));
    }

    [Fact]
    public async Task FilesARecordUnderTheSignatureThatAlignsWhenSeveralPass()
    {
        // The Google Workspace shape, as a real report lists it: google.com
        // first, the domain's own key second, both verified.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("google.com", "20230601") + DkimResult("example.com", "google")), "raw");

        Assert.Equal(("example.com", "google", "pass"), await StoredDkimAsync());
    }

    [Fact]
    public async Task DoesNotDependOnTheOrderTheSignaturesAreListedIn()
    {
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("example.com", "google") + DkimResult("google.com", "20230601")), "raw");

        Assert.Equal(("example.com", "google", "pass"), await StoredDkimAsync());
    }

    [Theory]
    [InlineData("mail.example.com", "example.com")]    // signs as a subdomain of the From domain
    [InlineData("example.com", "news.example.com")]    // signs as the parent of the From domain
    public async Task CountsASubdomainRelationAsAlignedWhichIsWhatTheDefaultModeDoes(string signer, string headerFrom)
    {
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("vendor.example.net", "v1") + DkimResult(signer, "s1"), headerFrom), "raw");

        Assert.Equal((signer, "s1", "pass"), await StoredDkimAsync());
    }

    [Fact]
    public async Task KeepsTheFirstPassingSignatureWhenNoneOfThemAligns()
    {
        // Nothing to choose between: a vendor signing as itself, twice. The
        // first stays, as it always did.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("vendor.example.net", "v1") + DkimResult("other.example.org", "o1")), "raw");

        Assert.Equal(("vendor.example.net", "v1", "pass"), await StoredDkimAsync());
    }

    [Fact]
    public async Task StillPrefersAPassingSignatureToAnAlignedOneThatFailed()
    {
        // Alignment decides between signatures that verified, and nothing
        // more. A vendor's verified signature says who really sent the mail;
        // the one beside it, claiming the From domain and failing, says only
        // that somebody tried - the case KeepsTheAuthResultAlongside... guards.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("example.com", "s1", "fail") + DkimResult("vendor.example.net", "v1"), dkimVerdict: "fail"), "raw");

        Assert.Equal(("vendor.example.net", "v1", "pass"), await StoredDkimAsync());
    }

    [Fact]
    public async Task FilesAnSpfResultTheSameWay()
    {
        // The HELO identity first, then the one DMARC reads.
        await _store.SaveAggregateAsync(OneRecord(
            SpfResult("vendor.example.net", "helo") + SpfResult("example.com", "mfrom")), "raw");

        Assert.Equal(("example.com", "pass"), await StoredSpfAsync());
    }

    [Fact]
    public async Task StoresAResultInLowerCaseWhateverTheReceiverCapitalised()
    {
        // The schema's values are lower case and one receiver writes "Fail".
        // SQLite compares text exactly, and every query asks for 'pass' as the
        // schema spells it, so a receiver that wrote "Pass" would have had
        // every message it passed counted as not having passed.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("example.com", "s1", "PASS") + SpfResult("example.com", "mfrom", "Fail")), "raw");

        Assert.Equal(("example.com", "s1", "pass"), await StoredDkimAsync());
        Assert.Equal(("example.com", "fail"), await StoredSpfAsync());
    }

    [Fact]
    public async Task DoesNotPreferAHeloResultToTheIdentityDmarcReads()
    {
        // A pass for the HELO name never counts toward DMARC, however well the
        // name lines up. Filed under it, a row would say SPF aligned for a
        // message the receiver failed on SPF.
        await _store.SaveAggregateAsync(OneRecord(
            SpfResult("vendor.example.net", "mfrom") + SpfResult("example.com", "helo")), "raw");

        Assert.Equal(("vendor.example.net", "pass"), await StoredSpfAsync());
    }

    [Fact]
    public async Task FallsBackToTheFirstPassWhenTheRecordNamesNoFromDomain()
    {
        // Nothing to align against, so nothing to prefer.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("google.com", "g1") + DkimResult("example.com", "s1"), headerFrom: ""), "raw");

        Assert.Equal(("google.com", "g1", "pass"), await StoredDkimAsync());
    }

    [Fact]
    public async Task StoredFactsExplainWhyTheReceiverPassedAGoogleSignedMessage()
    {
        // What a policy simulation needs from the store is facts that
        // reproduce the verdict the receiver reached. DKIM-only mail signed by
        // both google.com and the domain's own key did not: it came back
        // "unexplained" and was left out of every figure, and the same mail
        // arriving with a passing SPF as well was reported as resting on SPF
        // alone.
        await _store.SaveAggregateAsync(OneRecord(
            DkimResult("google.com", "20230601") + DkimResult("example.com", "google")
            + SpfResult("example.com", "mfrom", "fail")), "raw");

        var row = Assert.Single(await new PolicySimulationService(_dbPath).RowsAsync("example.com", 30));

        Assert.True(row.PassedAsEvaluated);
        Assert.True(PolicySimulator.WouldPass(row, strictDkim: false, strictSpf: false));
    }

    [Fact]
    public void RejectsAnEmptyDatabasePath()
    {
        Assert.Throws<ArgumentException>(() => new ReportStore("  "));
    }

    // ---- when the report actually arrived, as distinct from what it covers ----
    //
    // received_at used to be filled with the report's own date_end - the
    // value already sitting in the row beside it - so "when we got this" had
    // never once held when anything was got. Fixed by making the column
    // nullable and only ever writing to it what the caller explicitly knows.

    [Fact]
    public async Task WithNoArrivalTimeGivenNoneIsRecorded()
    {
        // The honest default. A report handed to the store without saying
        // when it arrived - which is every import from a file - must not have
        // one invented for it.
        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw", "msg-1");

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT received_at FROM aggregate_reports LIMIT 1";
        Assert.Equal(DBNull.Value, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task AGivenArrivalTimeIsStoredAsGiven()
    {
        // What the Graph collector has and a file import does not: a real
        // receivedDateTime off the message, carried through rather than
        // reconstructed from the report's own claimed window.
        var arrived = new DateTimeOffset(2026, 9, 20, 14, 3, 0, TimeSpan.Zero);

        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw", "msg-1", arrivedAt: arrived);

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT received_at FROM aggregate_reports LIMIT 1";
        var stored = (string)(await command.ExecuteScalarAsync())!;

        Assert.Equal("2026-09-20 14:03:00", stored);
    }

    [Fact]
    public async Task AnArrivalTimeIsNotSilentlyTheReportsOwnWindow()
    {
        // The specific regression. date_end for this fixture is not the
        // arrival time given here, and the two must not be conflated again.
        var arrived = new DateTimeOffset(2026, 9, 20, 14, 3, 0, TimeSpan.Zero);

        await _store.SaveAggregateAsync(Aggregate("google-aggregate.xml"), "raw", "msg-1", arrivedAt: arrived);

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT received_at, date_end FROM aggregate_reports LIMIT 1";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.NotEqual(reader.GetString(1), reader.GetString(0));
    }

    [Fact]
    public async Task TheSameIsTrueForTlsReports()
    {
        await _store.SaveTlsAsync(Tls("microsoft-tlsrpt.json"), "raw", "msg-1");

        await using var connection = await new ClientDatabases(_dbPath).OpenAsync(ClientScope.Organization(null));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT received_at FROM tls_reports LIMIT 1";
        Assert.Equal(DBNull.Value, await command.ExecuteScalarAsync());
    }
}
