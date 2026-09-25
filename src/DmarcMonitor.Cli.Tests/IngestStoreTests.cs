using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Forensic;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// What the collector counts when it hands a message's reports to the store.
///
/// The store answers null both for "I already have this" and for "there is
/// nothing to file this under", and the collector took every null as a
/// failure. A message whose report was already stored therefore stayed in the
/// source folder for good - read, refused and left again every run, with
/// nothing said - which is what a failure report did after its message failed
/// to move once. The two are told apart now, and a report that really was not
/// stored is still counted as one.
/// </summary>
public sealed class IngestStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-ingest-store-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public IngestStoreTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static AggregateReport Aggregate(string domain) =>
        AggregateReportParser.Parse($"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>receiver.example</org_name>
                <report_id>r-1</report_id>
                <date_range><begin>1757894400</begin><end>1757980799</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row><source_ip>192.0.2.25</source_ip><count>5</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
                <identifiers><header_from>{domain}</header_from></identifiers>
                <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """).Report!;

    private const string FailureReport = """
        From: dmarc-reports@receiver.example
        To: dmarc@example.org
        Subject: Auth Failure Report
        MIME-Version: 1.0
        Content-Type: multipart/report; report-type=feedback-report; boundary="b1"

        --b1
        Content-Type: message/feedback-report

        Feedback-Type: auth-failure
        User-Agent: Receiver-Feedback/1.0
        Version: 1
        Original-Mail-From: <billing@example.org>
        Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000
        Source-IP: 203.0.113.44
        Reported-Domain: example.org
        Auth-Failure: dmarc
        Delivery-Result: reject

        --b1--
        """;

    /// <summary>A report as the ingestor hands it over, attributed to <paramref name="attributedTo"/>.</summary>
    private static IngestedReport Ingested(AggregateReport report, string attributedTo) => new()
    {
        MessageId = "m1",
        FileName = "r.xml",
        Outcome = IngestOutcome.Ingested,
        Kind = ReportKind.DmarcAggregate,
        Domain = attributedTo,
        Aggregate = report,
    };

    private Task<IngestCommand.StoreOutcome> StoreAsync(IngestedReport report) =>
        IngestCommand.StoreAsync(_store, [report], CancellationToken.None);

    [Fact]
    public async Task AnAggregateReportAlreadyHeldIsCountedAsAlreadyStoredNotFailed()
    {
        var report = Ingested(Aggregate("example.org"), "example.org");

        Assert.Equal(new IngestCommand.StoreOutcome(1, 0, 0), await StoreAsync(report));
        Assert.Equal(new IngestCommand.StoreOutcome(0, 1, 0), await StoreAsync(report));
    }

    [Fact]
    public async Task ASubdomainsReportSortedIntoItsParentsFolderIsRecognizedToo()
    {
        // Attributed to the parent by the folder a rule sorted it into, and
        // stored under its own domain - which is where to look for it.
        var report = Ingested(Aggregate("mail.example.org"), "example.org");

        await StoreAsync(report);

        Assert.Equal(new IngestCommand.StoreOutcome(0, 1, 0), await StoreAsync(report));
    }

    [Fact]
    public async Task AFailureReportReadAgainIsAlreadyStoredSoItsMessageCanBeFiled()
    {
        var parsed = ForensicReportParser.Parse(FailureReport);
        Assert.True(parsed.Success, parsed.Error);

        var report = new IngestedReport
        {
            MessageId = "m1",
            FileName = "Auth Failure Report",
            Outcome = IngestOutcome.Ingested,
            Kind = ReportKind.DmarcFailure,
            Domain = "example.org",
            Forensic = parsed.Report,
            RawContent = FailureReport,
        };

        Assert.Equal(new IngestCommand.StoreOutcome(1, 0, 0), await StoreAsync(report));
        Assert.Equal(new IngestCommand.StoreOutcome(0, 1, 0), await StoreAsync(report));
    }

    [Fact]
    public async Task AReportTheStoreDeclinesIsCountedAsNotStored()
    {
        // The ingestor no longer hands one of these over, and this still has
        // to count it truthfully if anything ever does: nothing was stored.
        var parsed = TlsReportParser.Parse("""{"organization-name":"receiver.example","report-id":"t-1","policies":[]}""");
        Assert.True(parsed.Success, parsed.Error);

        var report = new IngestedReport
        {
            MessageId = "m1",
            FileName = "tls.json",
            Outcome = IngestOutcome.Ingested,
            Kind = ReportKind.TlsRpt,
            Tls = parsed.Report,
        };

        Assert.Equal(new IngestCommand.StoreOutcome(0, 0, 1), await StoreAsync(report));
    }
}
