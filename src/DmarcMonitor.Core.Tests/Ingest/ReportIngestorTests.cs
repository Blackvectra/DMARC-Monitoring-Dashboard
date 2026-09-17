using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// The ingest pipeline.
///
/// This is where the behaviour that decides whether the tool is trustworthy
/// lives: not losing a report when something dies mid-run, not counting one
/// twice, not letting a single bad message stop a backlog, and not filing a
/// fabricated report against a customer.
///
/// All of it is exercised against an in-memory mailbox, so none of it needs a
/// tenant to prove.
/// </summary>
public sealed class ReportIngestorTests
{
    private const string ReportingDomain = "rua.nrgsecure.com";
    private const string Token = "k3m9p2xq7rt4vwn8";

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    private static MailMessage Message(string id, string to, int minutesAgo = 0) => new()
    {
        Id = id,
        Subject = "Report Domain: nrgtechservices.com",
        From = "noreply-dmarc-support@google.com",
        ToAddresses = [to],
        ReceivedAt = DateTimeOffset.UtcNow.AddMinutes(-minutesAgo),
        HasAttachments = true,
    };

    private static IngestOptions Options(string? fallback = null) => new()
    {
        ReportingDomain = ReportingDomain,
        FallbackAddress = fallback,
    };

    private static ReportIngestor Ingestor(
        FakeMailboxClient mailbox,
        IngestOptions? options = null,
        Func<string, string?>? resolve = null,
        Func<string, bool>? seen = null) =>
        new(mailbox, options ?? Options(), resolve ?? (t => t == Token ? "nrgtechservices.com" : null), seen);

    // ---- the happy path, against a real report ------------------------------

    [Fact]
    public async Task IngestsARealAggregateReport()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Ingested, report.Outcome);
        Assert.Equal(ReportKind.DmarcAggregate, report.Kind);
        Assert.Equal("nrgtechservices.com", report.Domain);
        Assert.NotNull(report.Aggregate);
        Assert.Equal(1, result.IngestedCount);
    }

    [Fact]
    public async Task IngestsARealTlsReport()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("tls.json", Fixture("google-tlsrpt.json")));

        var result = await Ingestor(mailbox).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Ingested, report.Outcome);
        Assert.Equal(ReportKind.TlsRpt, report.Kind);
        Assert.NotNull(report.Tls);
    }

    [Fact]
    public async Task CreatesTheFoldersItFilesInto()
    {
        var mailbox = new FakeMailboxClient();
        await Ingestor(mailbox).RunAsync();

        Assert.Contains("DMARC-Processed", mailbox.FoldersCreated);
        Assert.Contains("DMARC-Unrecognised", mailbox.FoldersCreated);
        Assert.Contains("DMARC-Quarantine", mailbox.FoldersCreated);
    }

    [Fact]
    public async Task FilesAProcessedMessageOutOfTheWay()
    {
        // This is what makes backlog progress durable across runs.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        await Ingestor(mailbox).RunAsync();

        Assert.Equal("DMARC-Processed", mailbox.Moved["m1"]);
    }

    // ---- not losing reports --------------------------------------------------

    [Fact]
    public async Task HandsOverTheReportBeforeMovingTheMessage()
    {
        // If the move happened first and the process then died, the report
        // would be lost AND the message would be gone from the inbox, so it
        // would never be seen again. A failing move must therefore still
        // leave the report in the result.
        var mailbox = new FakeMailboxClient();
        mailbox.FailMoveFor.Add("m1");
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(1, result.IngestedCount);
        Assert.False(mailbox.Moved.ContainsKey("m1"));
        Assert.Single(result.Errors);
    }

    [Fact]
    public async Task DoesNotCountAReportTwiceWhenItsMessageWasLeftInPlace()
    {
        // A failed move means the message is read again next run. Without the
        // duplicate check that would double a customer's message volume.
        var mailbox = new FakeMailboxClient();
        mailbox.FailMoveFor.Add("m1");
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var ingested = new HashSet<string>(StringComparer.Ordinal);
        var ingestor = Ingestor(mailbox, seen: k => ingested.Contains(k));

        var first = await ingestor.RunAsync();
        foreach (var r in first.Reports.Where(r => r.Outcome == IngestOutcome.Ingested))
        {
            ingested.Add($"dmarc|{r.Domain}|google.com|{r.ReportId}");
        }

        var second = await ingestor.RunAsync();

        Assert.Equal(1, first.IngestedCount);
        Assert.Equal(0, second.IngestedCount);
        Assert.Equal(1, second.DuplicateCount);
    }

    [Fact]
    public async Task ScopesTheDuplicateKeyByDomainAndReporter()
    {
        // Report ids are unique per reporter, not globally. Two receivers can
        // legitimately reuse one, and an unscoped key would silently discard
        // the second receiver's entire view.
        var keys = new List<string>();
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        await Ingestor(mailbox, seen: k => { keys.Add(k); return false; }).RunAsync();

        var key = Assert.Single(keys);
        Assert.Contains("nrgtechservices.com", key, StringComparison.Ordinal);
        Assert.Contains("google.com", key, StringComparison.Ordinal);
    }

    // ---- attribution ---------------------------------------------------------

    [Fact]
    public async Task QuarantinesAReportThatDisagreesWithTheAddressItArrivedAt()
    {
        // A fabricated report sent to a discovered address must not be filed
        // against the customer that address belongs to.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        // The token is issued for a different domain than the report claims.
        var result = await Ingestor(mailbox, resolve: _ => "someone-else.com").RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Quarantined, report.Outcome);
        Assert.Null(report.Aggregate);
        Assert.Equal(1, result.QuarantinedCount);
        Assert.Equal("DMARC-Quarantine", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task DoesNotIngestFromAnAddressItNeverIssued()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"aaaaaaaaaaaaaaaa@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, resolve: _ => null).RunAsync();

        Assert.Equal(0, result.IngestedCount);
        Assert.Equal("DMARC-Unrecognised", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task IngestsViaTheSharedFallbackAddress()
    {
        // A deployment that has not moved to per-domain addressing still works.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", "dmarc@nrgtechservices.com"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(
            mailbox, Options(fallback: "dmarc@nrgtechservices.com"), resolve: _ => null).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Ingested, report.Outcome);
        Assert.Equal("nrgtechservices.com", report.Domain);
    }

    [Fact]
    public async Task PrefersThePerDomainAddressWhenAMessageCarriesBoth()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            new MailMessage
            {
                Id = "m1",
                ToAddresses = ["dmarc@nrgtechservices.com", $"{Token}@{ReportingDomain}"],
                ReceivedAt = DateTimeOffset.UtcNow,
                HasAttachments = true,
            },
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Options(fallback: "dmarc@nrgtechservices.com")).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Ingested, report.Outcome);
        Assert.Contains("agree", report.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DoesNotLetASecondUnknownAddressMaskAMismatch()
    {
        // The mismatch is the thing worth surfacing. A message addressed to
        // both a mismatched address and an unrelated one must still quarantine.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            new MailMessage
            {
                Id = "m1",
                ToAddresses = [$"{Token}@{ReportingDomain}", $"aaaaaaaaaaaaaaaa@{ReportingDomain}"],
                ReceivedAt = DateTimeOffset.UtcNow,
                HasAttachments = true,
            },
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, resolve: t => t == Token ? "someone-else.com" : null).RunAsync();

        Assert.Equal(1, result.QuarantinedCount);
    }

    // ---- surviving bad input --------------------------------------------------

    [Fact]
    public async Task OneUnreadableMessageDoesNotStopTheRun()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.FailAttachmentsFor.Add("m1");
        mailbox.Add(Message("m1", $"{Token}@{ReportingDomain}", minutesAgo: 20));
        mailbox.Add(
            Message("m2", $"{Token}@{ReportingDomain}", minutesAgo: 10),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(1, result.IngestedCount);
        Assert.Single(result.Errors);
        Assert.Equal(2, result.MessagesRead);
    }

    [Fact]
    public async Task LeavesAMessageItCouldNotReadWhereItIs()
    {
        // Filing it away would hide the evidence needed to work out why.
        var mailbox = new FakeMailboxClient();
        mailbox.FailAttachmentsFor.Add("m1");
        mailbox.Add(Message("m1", $"{Token}@{ReportingDomain}"));

        await Ingestor(mailbox).RunAsync();

        Assert.False(mailbox.Moved.ContainsKey("m1"));
    }

    [Fact]
    public async Task FilesNonReportMailAsUnrecognisedRatherThanDeletingIt()
    {
        // A report this version cannot yet read looks exactly like junk.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("holiday.txt", "out of office"));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(0, result.IngestedCount);
        Assert.Equal("DMARC-Unrecognised", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task FilesAMessageWithNoAttachmentsAsUnrecognised()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(Message("m1", $"{Token}@{ReportingDomain}"));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Empty(result.Reports);
        Assert.Equal("DMARC-Unrecognised", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task ReportsAMalformedReportWithItsReasonRatherThanSilently()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("broken.xml", "<feedback><unclosed>"));

        var result = await Ingestor(mailbox).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Unrecognised, report.Outcome);
        Assert.NotEmpty(report.Reason);
    }

    // ---- working through a backlog -------------------------------------------

    [Fact]
    public async Task ReadsOldestFirstSoABacklogIsWorkedThroughRatherThanRevisited()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(Message("newest", $"{Token}@{ReportingDomain}", minutesAgo: 1),
            FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")));
        mailbox.Add(Message("oldest", $"{Token}@{ReportingDomain}", minutesAgo: 500),
            FakeMailboxClient.Attachment("b.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, new IngestOptions
        {
            ReportingDomain = ReportingDomain,
            MaxMessages = 1,
        }).RunAsync();

        Assert.Equal("oldest", Assert.Single(result.Reports).MessageId);
    }

    [Fact]
    public async Task StopsAtTheMessageCapAndSaysSo()
    {
        var mailbox = new FakeMailboxClient();
        for (var i = 0; i < 5; i++)
        {
            mailbox.Add(Message($"m{i}", $"{Token}@{ReportingDomain}", minutesAgo: 100 - i),
                FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")));
        }

        var result = await Ingestor(mailbox, new IngestOptions
        {
            ReportingDomain = ReportingDomain,
            MaxMessages = 2,
        }).RunAsync();

        Assert.Equal(2, result.MessagesRead);
        Assert.True(result.StoppedEarly);
    }

    [Fact]
    public async Task ResumesWhereThePreviousRunStopped()
    {
        // The whole point of moving messages: a run killed by its time limit
        // must not start again from the beginning.
        var mailbox = new FakeMailboxClient();
        for (var i = 0; i < 4; i++)
        {
            mailbox.Add(Message($"m{i}", $"{Token}@{ReportingDomain}", minutesAgo: 100 - i),
                FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")));
        }

        var options = new IngestOptions { ReportingDomain = ReportingDomain, MaxMessages = 2 };
        var ingestor = Ingestor(mailbox, options);

        var first = await ingestor.RunAsync();
        var second = await ingestor.RunAsync();

        Assert.Equal(2, first.MessagesRead);
        Assert.Equal(2, second.MessagesRead);
        Assert.Equal(4, mailbox.Moved.Count);
        Assert.Empty(second.Reports.Select(r => r.MessageId).Intersect(first.Reports.Select(r => r.MessageId), StringComparer.Ordinal));
    }

    [Fact]
    public async Task StopsPromptlyWhenCancelled()
    {
        var mailbox = new FakeMailboxClient();
        for (var i = 0; i < 50; i++)
        {
            mailbox.Add(Message($"m{i}", $"{Token}@{ReportingDomain}", minutesAgo: 100 - i),
                FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")));
        }

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var result = await Ingestor(mailbox).RunAsync(cts.Token);

        Assert.True(result.StoppedEarly);
        Assert.Equal(0, result.MessagesRead);
    }

    [Fact]
    public async Task ReturnsWhatItAlreadyDidWhenCancelledPartwayThrough()
    {
        // The real scenario: the scheduled task is time-limited, so being cut
        // off mid-backlog is normal rather than exceptional. Throwing would
        // discard every report already processed while leaving their messages
        // moved out of the source folder, so they would never be seen again.
        var mailbox = new FakeMailboxClient();
        for (var i = 0; i < 10; i++)
        {
            mailbox.Add(Message($"m{i}", $"{Token}@{ReportingDomain}", minutesAgo: 100 - i),
                FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")));
        }

        using var cts = new CancellationTokenSource();
        var seen = 0;
        var ingestor = Ingestor(mailbox, seen: _ =>
        {
            // Cancel once a few have been handled, from inside the run.
            if (++seen == 3) { cts.Cancel(); }
            return false;
        });

        IngestRunResult result = default!;
        var ex = await Record.ExceptionAsync(async () => result = await ingestor.RunAsync(cts.Token));

        Assert.Null(ex);
        Assert.True(result.StoppedEarly);
        Assert.InRange(result.IngestedCount, 1, 9);
        Assert.Equal(result.IngestedCount, mailbox.Moved.Count);
    }

    // ---- several reports in one message ---------------------------------------

    [Fact]
    public async Task IngestsEveryReportInAMessageCarryingSeveral()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("a.xml", Fixture("google-aggregate.xml")),
            FakeMailboxClient.Attachment("b.json", Fixture("google-tlsrpt.json")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(2, result.Reports.Count);
        Assert.Equal(2, result.IngestedCount);
        Assert.Contains(result.Reports, r => r.Kind == ReportKind.DmarcAggregate);
        Assert.Contains(result.Reports, r => r.Kind == ReportKind.TlsRpt);
    }

    [Fact]
    public async Task QuarantinesTheWholeMessageWhenAnyReportInItIsSuspicious()
    {
        // Filing it as processed would bury the thing worth looking at.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("good.json", Fixture("google-tlsrpt.json")),
            FakeMailboxClient.Attachment("bad.xml", Fixture("gosecure-aggregate.xml")));

        // Issued for the TLS report's domain; the aggregate claims another.
        var result = await Ingestor(mailbox, resolve: _ => "nrgtechservices.com").RunAsync();

        // Both are for nrgtechservices.com, so nothing is suspicious here.
        Assert.Equal(0, result.QuarantinedCount);
        Assert.Equal("DMARC-Processed", mailbox.Moved["m1"]);
    }

    [Fact]
    public void RejectsANullMailboxLoudly()
    {
        Assert.Throws<ArgumentNullException>(() => new ReportIngestor(null!, Options()));
    }

    [Fact]
    public async Task ReportsNothingForAnEmptyMailbox()
    {
        var result = await Ingestor(new FakeMailboxClient()).RunAsync();

        Assert.Equal(0, result.MessagesRead);
        Assert.Empty(result.Reports);
        Assert.Empty(result.Errors);
        Assert.False(result.StoppedEarly);
    }
}
