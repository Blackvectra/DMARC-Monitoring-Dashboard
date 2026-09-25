using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// Reading a failure report out of the mailbox.
///
/// The ingest pipeline reads attachments, and for two report types that is all
/// there is. A DMARC failure report is different in a way that had it filed as
/// junk: it is a multipart/report whose PARTS are the report, and Graph
/// surfaces the copy of the failed message as an itemAttachment, which carries
/// no bytes. So the attachment list comes back empty and entirely correct, and
/// the report is in the message itself.
///
/// These tests are about that fallback: that it happens, that it does not
/// happen for ordinary report mail, and that a message which simply is not a
/// report still ends up exactly where it did before.
/// </summary>
public sealed class FailureReportIngestTests
{
    private const string ReportingDomain = "rua.nrgsecure.com";
    private const string Token = "k3m9p2xq7rt4vwn8";

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    private static MailMessage Message(string id, string to) => new()
    {
        Id = id,
        Subject = "Auth Failure Report for nrgtechservices.com",
        From = "dmarc-reports@receiver.example",
        ToAddresses = [to],
        ReceivedAt = DateTimeOffset.UtcNow.AddMinutes(-5),

        // False, and true: a failure report of this shape has no file
        // attachments, which is the whole reason the fallback exists.
        HasAttachments = false,
    };

    private const string FailureReport = """
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
        Original-Mail-From: <billing@nrgtechservices.com>
        Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000
        Source-IP: 203.0.113.44
        Reported-Domain: nrgtechservices.com
        Auth-Failure: dmarc
        Delivery-Result: none

        --b1
        Content-Type: text/rfc822-headers

        From: "Accounts" <billing@nrgtechservices.com>
        To: accounts@example.net
        Subject: Updated remittance details
        Message-ID: <20260915091202.9f3a@nrgtechservices.com>
        --b1--
        """;

    private static ReportIngestor Ingestor(FakeMailboxClient mailbox, Func<string, bool>? seen = null) =>
        new(mailbox,
            new IngestOptions { ReportingDomain = ReportingDomain },
            t => t == Token ? "nrgtechservices.com" : null,
            seen);

    [Fact]
    public async Task ReadsAFailureReportOutOfTheMessageItself()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.AddRaw(Message("m1", $"{Token}@{ReportingDomain}"), FailureReport);

        var result = await Ingestor(mailbox).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Ingested, report.Outcome);
        Assert.Equal(ReportKind.DmarcFailure, report.Kind);
        Assert.Equal("nrgtechservices.com", report.Domain);
        Assert.NotNull(report.Forensic);
        Assert.Equal("203.0.113.44", report.Forensic!.SourceIp);

        // Delivery-Result: none, so the forgery reached somebody. The thing
        // the whole feature is for.
        Assert.True(report.Forensic.WasDelivered);
    }

    /// <summary>
    /// The raw content is carried through, because storing one of these needs
    /// the text that arrived to hash - and there is no attachment to re-read.
    /// </summary>
    [Fact]
    public async Task CarriesWhatArrivedSoItCanBeDeduplicated()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.AddRaw(Message("m1", $"{Token}@{ReportingDomain}"), FailureReport);

        var report = Assert.Single((await Ingestor(mailbox).RunAsync()).Reports);

        Assert.Contains("Feedback-Type: auth-failure", report.RawContent, StringComparison.Ordinal);
    }

    /// <summary>
    /// Ordinary report mail must not pay for this.
    /// </summary>
    /// <remarks>
    /// A reporting mailbox holds thousands of aggregate reports and a handful
    /// of these. Fetching the whole of every message to look for a failure
    /// report that is almost never there would double the traffic of every
    /// run for nothing.
    /// </remarks>
    [Fact]
    public async Task AMessageWhoseAttachmentsHeldAReportIsNeverFetchedWhole()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        await Ingestor(mailbox).RunAsync();

        Assert.Empty(mailbox.RawFetches);
    }

    /// <summary>
    /// A message that is not a report is still filed as unrecognized, and is
    /// not thrown away because one more fetch came back with nothing.
    /// </summary>
    [Fact]
    public async Task OrdinaryMailIsStillFiledAsUnrecognized()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("lunch.txt", "Are you free at one?"));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
        Assert.DoesNotContain(result.Reports, r => r.Outcome == IngestOutcome.Ingested);
    }

    /// <summary>
    /// The attribution rules apply here as they do everywhere, and they matter
    /// more: these reports carry a real subject line, so one filed against the
    /// wrong customer is one client reading another client's mail.
    /// </summary>
    [Fact]
    public async Task AFailureReportForAnotherDomainIsQuarantined()
    {
        var mailbox = new FakeMailboxClient();

        // Delivered to the per-domain address issued for nrgtechservices.com,
        // and the report inside is about somebody else's domain.
        mailbox.AddRaw(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FailureReport.Replace("nrgtechservices.com", "someone-elses.example", StringComparison.Ordinal));

        var result = await Ingestor(mailbox).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Quarantined, report.Outcome);
        Assert.Equal("DMARC-Quarantine", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task TheSameFailureReportIsNotIngestedTwice()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.AddRaw(Message("m1", $"{Token}@{ReportingDomain}"), FailureReport);

        var result = await Ingestor(mailbox, seen: _ => true).RunAsync();

        Assert.Equal(IngestOutcome.Duplicate, Assert.Single(result.Reports).Outcome);
    }

    /// <summary>
    /// A mailbox that cannot produce the raw message is a mailbox with one
    /// more unreadable item in it, not a run that stops.
    /// </summary>
    [Fact]
    public async Task AMessageWithNothingInItAtAllDoesNotEndTheRun()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(Message("m1", $"{Token}@{ReportingDomain}"));
        mailbox.AddRaw(Message("m2", $"{Token}@{ReportingDomain}"), FailureReport);

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(2, result.MessagesRead);
        Assert.Contains(result.Reports, r => r.Outcome == IngestOutcome.Ingested);
    }
}
