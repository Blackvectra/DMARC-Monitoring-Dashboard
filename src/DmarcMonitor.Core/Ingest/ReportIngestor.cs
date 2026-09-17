using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Ingest;

/// <summary>Settings for one ingest run.</summary>
public sealed record IngestOptions
{
    /// <summary>Folder to read from.</summary>
    public string SourceFolder { get; init; } = "Inbox";

    /// <summary>Where a successfully ingested report is filed.</summary>
    public string ProcessedFolder { get; init; } = "DMARC-Processed";

    /// <summary>
    /// Where mail that is not a report is filed. Kept rather than deleted:
    /// a report the parser does not yet understand looks exactly like junk,
    /// and deleting it destroys the evidence needed to fix that.
    /// </summary>
    public string UnrecognisedFolder { get; init; } = "DMARC-Unrecognised";

    /// <summary>
    /// Where a report is filed when the delivery address and its contents
    /// disagree. Separate from unrecognised because this is the shape of an
    /// injected report and somebody should look at it.
    /// </summary>
    public string QuarantineFolder { get; init; } = "DMARC-Quarantine";

    /// <summary>The subdomain per-domain report addresses are issued under.</summary>
    public string ReportingDomain { get; init; } = "";

    /// <summary>Optional shared address, for deployments not yet using per-domain addressing.</summary>
    public string? FallbackAddress { get; init; }

    /// <summary>
    /// Stop after this many messages. A first run against a large backlog has
    /// to fit inside a scheduled window; progress is durable, so the next run
    /// continues from where this one stopped.
    /// </summary>
    public int MaxMessages { get; init; } = 500;
}

public enum IngestOutcome
{
    /// <summary>Parsed, attributed and ready to store.</summary>
    Ingested,

    /// <summary>Already seen. Not an error.</summary>
    Duplicate,

    /// <summary>Not a report, or a report this version cannot read.</summary>
    Unrecognised,

    /// <summary>The delivery address and the report disagree about the domain.</summary>
    Quarantined,
}

/// <summary>One report recovered from one message.</summary>
public sealed record IngestedReport
{
    public required string MessageId { get; init; }
    public required string FileName { get; init; }
    public required IngestOutcome Outcome { get; init; }
    public ReportKind Kind { get; init; } = ReportKind.Unknown;

    /// <summary>The domain this is filed under, once attribution succeeded.</summary>
    public string Domain { get; init; } = "";

    /// <summary>Unique id from the report, used to avoid ingesting it twice.</summary>
    public string ReportId { get; init; } = "";

    public AggregateReport? Aggregate { get; init; }
    public TlsReport? Tls { get; init; }

    /// <summary>Plain-English explanation, safe to log or show an operator.</summary>
    public string Reason { get; init; } = "";
}

public sealed record IngestRunResult
{
    public int MessagesRead { get; init; }
    public int MessagesMoved { get; init; }
    public IReadOnlyList<IngestedReport> Reports { get; init; } = [];

    /// <summary>
    /// Messages that threw. Kept per-message so one failure is visible
    /// without having taken the run down.
    /// </summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>True when the message cap was reached and a backlog remains.</summary>
    public bool StoppedEarly { get; init; }

    public int IngestedCount => Reports.Count(r => r.Outcome == IngestOutcome.Ingested);
    public int QuarantinedCount => Reports.Count(r => r.Outcome == IngestOutcome.Quarantined);
    public int DuplicateCount => Reports.Count(r => r.Outcome == IngestOutcome.Duplicate);
    public int UnrecognisedCount => Reports.Count(r => r.Outcome == IngestOutcome.Unrecognised);
}

/// <summary>
/// Reads the reporting mailbox and turns it into parsed, attributed reports.
///
/// The ordering rule that matters: a message is moved only AFTER its reports
/// have been handed to the caller. Moving first would lose a report whenever
/// the process died between the move and the store, and the message would
/// never be seen again because it is no longer in the source folder.
/// </summary>
public sealed class ReportIngestor
{
    private readonly IMailboxClient _mailbox;
    private readonly IngestOptions _options;
    private readonly Func<string, string?> _resolveToken;
    private readonly Func<string, bool> _isAlreadyIngested;

    /// <param name="resolveToken">
    /// Maps an issued report-address token to the domain it was issued for.
    /// Returns null for a token that is not currently issued.
    /// </param>
    /// <param name="isAlreadyIngested">
    /// True when a report id has been stored before. Reports are re-sent, and
    /// a message left in place by a failed move would otherwise be counted
    /// twice, inflating a customer's volume.
    /// </param>
    public ReportIngestor(
        IMailboxClient mailbox,
        IngestOptions options,
        Func<string, string?>? resolveToken = null,
        Func<string, bool>? isAlreadyIngested = null)
    {
        _mailbox = mailbox ?? throw new ArgumentNullException(nameof(mailbox));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _resolveToken = resolveToken ?? (_ => null);
        _isAlreadyIngested = isAlreadyIngested ?? (_ => false);
    }

    public async Task<IngestRunResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var reports = new List<IngestedReport>();
        var errors = new List<string>();
        var read = 0;
        var moved = 0;
        var stoppedEarly = false;

        var processedId = await _mailbox.EnsureFolderAsync(_options.ProcessedFolder, cancellationToken).ConfigureAwait(false);
        var unrecognisedId = await _mailbox.EnsureFolderAsync(_options.UnrecognisedFolder, cancellationToken).ConfigureAwait(false);
        var quarantineId = await _mailbox.EnsureFolderAsync(_options.QuarantineFolder, cancellationToken).ConfigureAwait(false);

        // The enumeration itself can throw on cancellation, so the whole loop
        // is wrapped. A cancelled run has to RETURN what it already did: the
        // scheduled task is time-limited, so being cut off mid-backlog is the
        // normal case, not an exceptional one. Throwing here would discard
        // every report processed before the deadline and leave their messages
        // moved out of the source folder, so they would never be seen again.
        try
        {
        await foreach (var message in _mailbox.GetMessagesAsync(_options.SourceFolder, cancellationToken).ConfigureAwait(false))
        {
            if (cancellationToken.IsCancellationRequested) { stoppedEarly = true; break; }
            if (read >= _options.MaxMessages) { stoppedEarly = true; break; }
            read++;

            List<IngestedReport> fromThisMessage;
            try
            {
                fromThisMessage = await ProcessMessageAsync(message, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                stoppedEarly = true;
                break;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // One unreadable message must never stop a run working through
                // a backlog of thousands. It is left in place deliberately, so
                // it can be looked at rather than quietly filed away.
                errors.Add($"{message.Id}: {ex.Message}");
                continue;
            }

            reports.AddRange(fromThisMessage);

            // Move only after the reports are in hand. Reversing this loses a
            // report if the process dies in between, and the message is gone
            // from the source folder so it is never seen again.
            var destination = ChooseDestination(fromThisMessage, processedId, unrecognisedId, quarantineId);
            try
            {
                await _mailbox.MoveMessageAsync(message.Id, destination, cancellationToken).ConfigureAwait(false);
                moved++;
            }
            catch (OperationCanceledException)
            {
                stoppedEarly = true;
                break;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A failed move is survivable: the report was already handed
                // over, and the duplicate check stops it being counted twice
                // when this message is read again next run.
                errors.Add($"{message.Id}: could not be filed: {ex.Message}");
            }
        }
        }
        catch (OperationCanceledException)
        {
            stoppedEarly = true;
        }

        return new IngestRunResult
        {
            MessagesRead = read,
            MessagesMoved = moved,
            Reports = reports,
            Errors = errors,
            StoppedEarly = stoppedEarly,
        };
    }

    /// <summary>
    /// Where a message goes once processed. Worst outcome wins: a message
    /// carrying one good report and one quarantined report is quarantined, so
    /// the thing worth looking at is not buried in the processed folder.
    /// </summary>
    private static string ChooseDestination(
        IReadOnlyList<IngestedReport> reports, string processed, string unrecognised, string quarantine)
    {
        if (reports.Any(r => r.Outcome == IngestOutcome.Quarantined)) { return quarantine; }
        if (reports.Count == 0) { return unrecognised; }
        if (reports.All(r => r.Outcome == IngestOutcome.Unrecognised)) { return unrecognised; }
        return processed;
    }

    private async Task<List<IngestedReport>> ProcessMessageAsync(MailMessage message, CancellationToken ct)
    {
        var results = new List<IngestedReport>();
        var attachments = await _mailbox.GetAttachmentsAsync(message.Id, ct).ConfigureAwait(false);

        foreach (var attachment in attachments)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var extracted in ReportAttachment.Extract(attachment.Name, attachment.Content))
            {
                results.Add(extracted.Kind switch
                {
                    ReportKind.DmarcAggregate => HandleAggregate(message, extracted),
                    ReportKind.TlsRpt => HandleTls(message, extracted),
                    _ => Unrecognised(message, extracted.FileName, "The attachment is not a report this version can read."),
                });
            }
        }

        return results;
    }

    private IngestedReport HandleAggregate(MailMessage message, ExtractedReport extracted)
    {
        var parsed = AggregateReportParser.Parse(extracted.Content);
        if (!parsed.Success)
        {
            return Unrecognised(message, extracted.FileName, parsed.Error);
        }

        var report = parsed.Report!;
        var attribution = Attribute(message, report.Policy.Domain);

        if (attribution.Outcome == AttributionOutcome.DomainMismatch)
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Quarantined,
                Kind = ReportKind.DmarcAggregate,
                Domain = attribution.Domain,
                ReportId = report.Metadata.ReportId,
                Reason = attribution.Reason,
            };
        }

        if (!attribution.ShouldIngest)
        {
            return Unrecognised(message, extracted.FileName, attribution.Reason);
        }

        // Scope the duplicate key by domain. Report ids are only unique per
        // reporter, so two receivers can legitimately reuse one, and an
        // unscoped key would silently discard the second.
        var key = $"dmarc|{attribution.Domain}|{report.Metadata.OrgName}|{report.Metadata.ReportId}";
        if (_isAlreadyIngested(key))
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Duplicate,
                Kind = ReportKind.DmarcAggregate,
                Domain = attribution.Domain,
                ReportId = report.Metadata.ReportId,
                Reason = "This report has already been ingested.",
            };
        }

        return new IngestedReport
        {
            MessageId = message.Id,
            FileName = extracted.FileName,
            Outcome = IngestOutcome.Ingested,
            Kind = ReportKind.DmarcAggregate,
            Domain = attribution.Domain,
            ReportId = report.Metadata.ReportId,
            Aggregate = report,
            Reason = attribution.Reason,
        };
    }

    private IngestedReport HandleTls(MailMessage message, ExtractedReport extracted)
    {
        var parsed = TlsReportParser.Parse(extracted.Content);
        if (!parsed.Success)
        {
            return Unrecognised(message, extracted.FileName, parsed.Error);
        }

        var report = parsed.Report!;
        var domain = report.Policies.Count > 0 ? report.Policies[0].Policy.Domain : "";
        var attribution = Attribute(message, domain);

        if (attribution.Outcome == AttributionOutcome.DomainMismatch)
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Quarantined,
                Kind = ReportKind.TlsRpt,
                Domain = attribution.Domain,
                ReportId = report.ReportId,
                Reason = attribution.Reason,
            };
        }

        if (!attribution.ShouldIngest)
        {
            return Unrecognised(message, extracted.FileName, attribution.Reason);
        }

        var key = $"tls|{attribution.Domain}|{report.OrganizationName}|{report.ReportId}";
        if (_isAlreadyIngested(key))
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Duplicate,
                Kind = ReportKind.TlsRpt,
                Domain = attribution.Domain,
                ReportId = report.ReportId,
                Reason = "This report has already been ingested.",
            };
        }

        return new IngestedReport
        {
            MessageId = message.Id,
            FileName = extracted.FileName,
            Outcome = IngestOutcome.Ingested,
            Kind = ReportKind.TlsRpt,
            Domain = attribution.Domain,
            ReportId = report.ReportId,
            Tls = report,
            Reason = attribution.Reason,
        };
    }

    /// <summary>
    /// Attributes using whichever recipient address resolves.
    /// </summary>
    /// <remarks>
    /// A message can carry several To addresses. The best outcome across them
    /// wins, so a report addressed to both a per-domain address and a shared
    /// one is attributed by the stronger of the two rather than by whichever
    /// happened to be listed first.
    /// </remarks>
    private AttributionResult Attribute(MailMessage message, string reportDomain)
    {
        AttributionResult? best = null;

        foreach (var to in message.ToAddresses)
        {
            var result = ReportAttribution.Attribute(
                to, reportDomain, _options.ReportingDomain, _resolveToken, _options.FallbackAddress);

            if (result.Outcome == AttributionOutcome.Attributed) { return result; }

            // A mismatch outranks unknown: it is the case worth surfacing, and
            // a second address resolving to nothing must not mask it.
            if (best is null ||
                (best.Outcome == AttributionOutcome.UnknownAddress && result.Outcome != AttributionOutcome.UnknownAddress))
            {
                best = result;
            }
        }

        return best ?? ReportAttribution.Attribute(
            null, reportDomain, _options.ReportingDomain, _resolveToken, _options.FallbackAddress);
    }

    private static IngestedReport Unrecognised(MailMessage message, string fileName, string reason) => new()
    {
        MessageId = message.Id,
        FileName = fileName,
        Outcome = IngestOutcome.Unrecognised,
        Reason = reason,
    };
}
