using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// The ingest pipeline.
///
/// This is where the behavior that decides whether the tool is trustworthy
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
    public async Task CarriesTheMessagesRealArrivalTime()
    {
        // What the store needs to record a real received_at instead of
        // inventing one from the report's own claimed window. The message is
        // the only thing that actually knows when it arrived.
        var arrived = DateTimeOffset.UtcNow.AddMinutes(-47);
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            new MailMessage
            {
                Id = "m1",
                Subject = "Report Domain: nrgtechservices.com",
                From = "noreply-dmarc-support@google.com",
                ToAddresses = [$"{Token}@{ReportingDomain}"],
                ReceivedAt = arrived,
                HasAttachments = true,
            },
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(arrived, Assert.Single(result.Reports).ArrivedAt);
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
        Assert.Contains("DMARC-Unrecognized", mailbox.FoldersCreated);
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
        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task LeavesAGenuineReportToAnUnknownAddressInTheMailbox()
    {
        // The shared address is configured as the mailbox, but the rua= tag
        // points at an alias of it. Filing the report as unrecognized would
        // lose it for good: nothing reads that folder again. It stays put,
        // says where it was sent, and the run after the fix picks it up.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", "DMARC Reports <dmarc-reports@nrgtechservices.com>"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(
            mailbox, Options(fallback: "dmarc@nrgtechservices.com"), resolve: _ => null).RunAsync();

        var report = Assert.Single(result.Reports);
        Assert.Equal(IngestOutcome.Unattributed, report.Outcome);
        Assert.Equal(ReportKind.DmarcAggregate, report.Kind);
        Assert.Equal("nrgtechservices.com", report.Domain);
        Assert.Equal(["dmarc-reports@nrgtechservices.com"], report.DeliveredTo);
        Assert.Equal(1, result.UnattributedCount);
        Assert.Equal(["dmarc-reports@nrgtechservices.com"], result.UnattributedAddresses);
        Assert.Equal(0, result.UnrecognizedCount);
        Assert.False(mailbox.Moved.ContainsKey("m1"));

        // Corrected configuration, same mailbox: ingested and filed.
        var again = await Ingestor(
            mailbox, Options(fallback: "dmarc-reports@nrgtechservices.com"), resolve: _ => null).RunAsync();

        Assert.Equal(1, again.IngestedCount);
        Assert.Equal("DMARC-Processed", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task StillFilesAReportToAStaleIssuedAddressAsUnrecognized()
    {
        // A per-domain address whose token no longer resolves is the expected
        // tail after a domain is removed, not a configuration mistake, so it
        // is filed away rather than re-read every hour for ever.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"aaaaaaaaaaaaaaaa@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Options(fallback: "dmarc@nrgtechservices.com"), resolve: _ => null).RunAsync();

        Assert.Equal(0, result.UnattributedCount);
        Assert.Equal(1, result.UnrecognizedCount);
        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task AQuarantinedReportStillOutranksAnUnattributedOne()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", "dmarc-reports@nrgtechservices.com"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")),
            FakeMailboxClient.Attachment("tls.json", Fixture("google-tlsrpt.json")));
        mailbox.Add(
            Message("m2", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(
            mailbox, Options(fallback: "dmarc@nrgtechservices.com"),
            resolve: t => t == Token ? "someone-else.com" : null).RunAsync();

        Assert.Equal(2, result.UnattributedCount);
        Assert.False(mailbox.Moved.ContainsKey("m1"));
        Assert.Equal("DMARC-Quarantine", mailbox.Moved["m2"]);
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
    public async Task FilesNonReportMailAsUnrecognizedRatherThanDeletingIt()
    {
        // A report this version cannot yet read looks exactly like junk.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("holiday.txt", "out of office"));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(0, result.IngestedCount);
        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task FilesAMessageWithNoAttachmentsAsUnrecognized()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(Message("m1", $"{Token}@{ReportingDomain}"));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Empty(result.Reports);
        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
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
        Assert.Equal(IngestOutcome.Unrecognized, report.Outcome);
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

    // ---- stored before filed ------------------------------------------------

    [Fact]
    public async Task AMessageIsNotFiledUntilItsReportsAreStored()
    {
        // The window this closes: reports were parsed into a list, every
        // message was moved out of the source folder as the run went, and the
        // list was only written to the database once the whole run returned.
        // A process killed in between left the messages filed and the reports
        // nowhere - and the next run reads the source folder, not Processed,
        // so they were never collected again. A time-limited scheduled task
        // being cut off mid-backlog is the normal case, not an exotic one.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var order = new List<string>();

        var ingestor = new ReportIngestor(
            mailbox, Options(), t => t == Token ? "nrgtechservices.com" : null, null,
            (found, _) => { order.Add("stored"); return Task.FromResult(true); });

        mailbox.OnMove = _ => order.Add("filed");

        await ingestor.RunAsync();

        Assert.Equal(["stored", "filed"], order);
    }

    [Fact]
    public async Task AMessageWhoseReportsCouldNotBeStoredStaysWhereItIs()
    {
        // The safe direction. A message read twice is caught by the duplicate
        // check; a message filed and never stored is gone.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var ingestor = new ReportIngestor(
            mailbox, Options(), t => t == Token ? "nrgtechservices.com" : null, null,
            (_, _) => Task.FromResult(false));

        var result = await ingestor.RunAsync();

        Assert.Empty(mailbox.Moved);
        Assert.Equal(0, result.MessagesMoved);
    }

    [Fact]
    public async Task AStoreThatThrowsLeavesTheMessageAndIsReported()
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var ingestor = new ReportIngestor(
            mailbox, Options(), t => t == Token ? "nrgtechservices.com" : null, null,
            (_, _) => throw new InvalidOperationException("database is locked"));

        var result = await ingestor.RunAsync();

        Assert.Empty(mailbox.Moved);
        Assert.Contains(result.Errors, e => e.Contains("left in place", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithNoStoreToCallTheRunBehavesAsItAlwaysDid()
    {
        // The callback is optional, so nothing that constructs an ingestor
        // without one changes behavior.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Equal(1, result.MessagesMoved);
        Assert.Single(mailbox.Moved);
    }

    // ---- deleting stored mail ------------------------------------------------
    //
    // A reporting mailbox grows without limit, and filing into the processed
    // folder moves the problem rather than solving it - same mailbox, same
    // quota. So a run can be told to delete instead. Most of what follows
    // asserts silence: what this must NOT delete is the whole safety of it,
    // and a missing deletion is far easier to notice than a wrong one, because
    // a wrong one is only noticed when somebody goes looking for the evidence
    // and it is not there.

    private static IngestOptions Deleting(DeleteProcessed mode) => new()
    {
        ReportingDomain = ReportingDomain,
        DeleteProcessed = mode,
    };

    [Theory]
    [InlineData(DeleteProcessed.Soft, false)]
    [InlineData(DeleteProcessed.Permanent, true)]
    public async Task DeletesAStoredReportRatherThanFilingIt(DeleteProcessed mode, bool permanent)
    {
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Deleting(mode)).RunAsync();

        Assert.Equal(1, result.MessagesDeleted);
        Assert.Equal(0, result.MessagesMoved);
        Assert.True(mailbox.Deleted.ContainsKey("m1"));
        Assert.Equal(permanent, mailbox.Deleted["m1"]);
        Assert.Empty(mailbox.Moved);
    }

    [Fact]
    public async Task KeepsEverythingByDefault()
    {
        // The setting has to be asked for. A version that started deleting on
        // upgrade would empty a mailbox nobody had decided to empty.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox).RunAsync();

        Assert.Empty(mailbox.Deleted);
        Assert.Equal(0, result.MessagesDeleted);
        Assert.Equal("DMARC-Processed", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task NeverDeletesAReportItCouldNotRead()
    {
        // A report this version cannot parse looks exactly like junk, and it
        // is the only copy of the evidence needed to teach the parser to read
        // it. Deleting it makes that fix impossible.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("notes.txt", "this is not a report"));

        var result = await Ingestor(mailbox, Deleting(DeleteProcessed.Permanent)).RunAsync();

        Assert.Empty(mailbox.Deleted);
        Assert.Equal(0, result.MessagesDeleted);
        Assert.Equal("DMARC-Unrecognized", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task NeverDeletesAQuarantinedReport()
    {
        // The shape of an injected report: the address it arrived at and the
        // domain inside it disagree. Somebody has to be able to look at it.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Deleting(DeleteProcessed.Permanent), resolve: _ => "someone-else.com")
            .RunAsync();

        Assert.Empty(mailbox.Deleted);
        Assert.Equal(0, result.MessagesDeleted);
        Assert.Equal("DMARC-Quarantine", mailbox.Moved["m1"]);
    }

    [Fact]
    public async Task NeverDeletesAGenuineReportItCouldNotAttribute()
    {
        // A configuration mistake, not junk. It stays in the source folder so
        // that correcting the shared address and running again collects it.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", "dmarc@somewhere-else.example"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Deleting(DeleteProcessed.Permanent)).RunAsync();

        Assert.Equal(1, result.UnattributedCount);
        Assert.Empty(mailbox.Deleted);
        Assert.Empty(mailbox.Moved);
    }

    [Fact]
    public async Task NeverDeletesAMessageWhoseReportsCouldNotBeStored()
    {
        // The ordering rule, and it matters more here than for a move. A
        // message filed in Processed and never stored can be dragged back; a
        // message deleted and never stored is gone.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var ingestor = new ReportIngestor(
            mailbox, Deleting(DeleteProcessed.Permanent),
            t => t == Token ? "nrgtechservices.com" : null,
            _ => false,
            (_, _) => Task.FromResult(false));

        var result = await ingestor.RunAsync();

        Assert.Empty(mailbox.Deleted);
        Assert.Empty(mailbox.Moved);
        Assert.Equal(0, result.MessagesDeleted);
    }

    [Fact]
    public async Task DeletesAReportAlreadySeenBecauseItIsAlreadyStored()
    {
        // Re-sent reports are most of what fills a mailbox, and a duplicate is
        // by definition already in the database.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));

        var result = await Ingestor(mailbox, Deleting(DeleteProcessed.Soft), seen: _ => true).RunAsync();

        Assert.Equal(1, result.DuplicateCount);
        Assert.Equal(1, result.MessagesDeleted);
        Assert.True(mailbox.Deleted.ContainsKey("m1"));
    }

    [Fact]
    public async Task AFailedDeleteIsSurvivableAndLeavesTheMessageWhereItIs()
    {
        // The next run reads it again, the duplicate check catches it, and it
        // is deleted then. One mailbox error must not take down a backlog.
        var mailbox = new FakeMailboxClient();
        mailbox.Add(
            Message("m1", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));
        mailbox.Add(
            Message("m2", $"{Token}@{ReportingDomain}"),
            FakeMailboxClient.Attachment("google.xml", Fixture("google-aggregate.xml")));
        mailbox.FailDeleteFor.Add("m1");

        var result = await Ingestor(mailbox, Deleting(DeleteProcessed.Permanent)).RunAsync();

        Assert.Equal(1, result.MessagesDeleted);
        Assert.True(mailbox.Deleted.ContainsKey("m2"));
        Assert.False(mailbox.Deleted.ContainsKey("m1"));
        Assert.Contains(result.Errors, e => e.Contains("could not be deleted", StringComparison.Ordinal));
    }
}
