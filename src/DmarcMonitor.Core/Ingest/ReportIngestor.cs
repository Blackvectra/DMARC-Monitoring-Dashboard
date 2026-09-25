using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Forensic;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Ingest;

/// <summary>Settings for one ingest run.</summary>
public sealed record IngestOptions
{
    /// <summary>
    /// The folders to read, by display name, in the order they are read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Inbox unless somebody says otherwise, which is how it has always been.
    /// It became a list because the mailbox this was built for has Outlook
    /// rules filing most of its reports into folders BESIDE Inbox, not inside
    /// it - nine of them, literally named like <c>DMARC\example.org</c> - and
    /// a collector that could only read Inbox never saw them.
    /// </para>
    /// <para>
    /// Each is a folder at the top of the mailbox (or a well-known name such as
    /// Inbox), matched by its whole name: a backslash is part of the name, not
    /// a path. One that is not there is reported, never created.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> SourceFolders { get; init; } = ["Inbox"];

    /// <summary>Where a successfully ingested report is filed.</summary>
    public string ProcessedFolder { get; init; } = "DMARC-Processed";

    /// <summary>
    /// Where mail that is not a report is filed. Kept rather than deleted:
    /// a report the parser does not yet understand looks exactly like junk,
    /// and deleting it destroys the evidence needed to fix that.
    /// </summary>
    public string UnrecognizedFolder { get; init; } = "DMARC-Unrecognized";

    /// <summary>
    /// Where a report is filed when the delivery address and its contents
    /// disagree. Separate from unrecognized because this is the shape of an
    /// injected report and somebody should look at it.
    /// </summary>
    public string QuarantineFolder { get; init; } = "DMARC-Quarantine";

    /// <summary>
    /// What to do with a message once its reports are safely stored.
    /// </summary>
    /// <remarks>
    /// Filing is the default and deleting is not, because the mailbox is the
    /// only copy of a customer's evidence until the database has it. Deleting
    /// applies to nothing else: see <see cref="DeleteProcessed"/>.
    /// </remarks>
    public DeleteProcessed DeleteProcessed { get; init; } = DeleteProcessed.Keep;

    /// <summary>The subdomain per-domain report addresses are issued under.</summary>
    public string ReportingDomain { get; init; } = "";

    /// <summary>
    /// Also read the folders directly inside each source folder.
    /// </summary>
    /// <remarks>
    /// Sorting reports into a folder per domain with a mail rule is how an MSP
    /// normally organizes a shared dmarc@ mailbox. Without this, reading
    /// "DMARC" finds nothing while hundreds of reports sit one level below,
    /// and nothing says so.
    /// </remarks>
    public bool IncludeChildFolders { get; init; } = true;

    /// <summary>Optional shared address, for deployments not yet using per-domain addressing.</summary>
    public string? FallbackAddress { get; init; }

    /// <summary>
    /// Stop after this many messages. A first run against a large backlog has
    /// to fit inside a scheduled window; progress is durable, so the next run
    /// continues from where this one stopped.
    /// </summary>
    public int MaxMessages { get; init; } = 500;
}

/// <summary>
/// What becomes of a message whose reports are now in the database.
/// </summary>
/// <remarks>
/// <para>
/// A reporting mailbox grows without limit. Every receiver sends for every
/// domain every day, so filing the processed mail into another folder of the
/// same mailbox moves the problem rather than solving it - it is the same
/// quota.
/// </para>
/// <para>
/// This applies to processed mail and to nothing else. Mail the parser did
/// not understand, mail whose delivery address and contents disagreed, and
/// mail delivered somewhere this deployment does not recognize are all kept
/// wherever they are now, whatever this is set to. Each of the three is
/// evidence of something to fix, and a report this version cannot read looks
/// exactly like junk right up until somebody reads it and improves the parser.
/// </para>
/// </remarks>
public enum DeleteProcessed
{
    /// <summary>File it in the processed folder. The default, and the only one that keeps the mail.</summary>
    Keep,

    /// <summary>
    /// Put it in Deleted Items, where a person can get it back.
    /// </summary>
    /// <remarks>
    /// Deleted Items counts against the mailbox quota, so this empties the
    /// inbox without giving any space back until a retention policy clears
    /// the folder. It is the right first setting for somebody who has not
    /// watched this run against their mailbox yet.
    /// </remarks>
    Soft,

    /// <summary>
    /// Remove it from the mailbox proper.
    /// </summary>
    /// <remarks>
    /// In Exchange Online this lands in Recoverable Items, which has a quota
    /// of its own, so this is the setting that actually returns the space.
    /// Still recoverable for the tenant's deleted-item retention period.
    /// </remarks>
    Permanent,
}

public enum IngestOutcome
{
    /// <summary>Parsed, attributed and ready to store.</summary>
    Ingested,

    /// <summary>Already seen. Not an error.</summary>
    Duplicate,

    /// <summary>Not a report, or a report this version cannot read.</summary>
    Unrecognized,

    /// <summary>
    /// A genuine report delivered to an address this deployment does not
    /// recognize at all: not a per-domain address, not the shared one. That is
    /// almost always the shared address being configured wrong (an alias, a
    /// group, a UPN), so the message is left where it is for the run after the
    /// configuration is corrected rather than filed away as junk.
    /// </summary>
    Unattributed,

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
    public ForensicReport? Forensic { get; init; }

    /// <summary>
    /// The report exactly as it arrived, for the caller that has to store it.
    /// </summary>
    /// <remarks>
    /// Only filled for failure reports, and only because storing one needs the
    /// original text to hash for deduplication. The other two are re-read from
    /// the attachment by the caller; a failure report may have come from the
    /// message body instead, which the caller does not have.
    /// </remarks>
    public string RawContent { get; init; } = "";

    /// <summary>
    /// When the message carrying this report arrived, or null when unknown.
    /// </summary>
    /// <remarks>
    /// Read from the mailbox and carried through rather than reconstructed.
    /// The report itself says only which period it covers; how long the
    /// reporter then took to send it is a fact only the message has, and it
    /// was being thrown away here.
    /// </remarks>
    public DateTimeOffset? ArrivedAt { get; init; }

    /// <summary>Plain-English explanation, safe to log or show an operator.</summary>
    public string Reason { get; init; } = "";

    /// <summary>
    /// The addresses the message was delivered to. Filled in for an
    /// unattributed report, because that is exactly what the operator needs
    /// to see to fix the configuration.
    /// </summary>
    public IReadOnlyList<string> DeliveredTo { get; init; } = [];
}

public sealed record IngestRunResult
{
    public int MessagesRead { get; init; }
    public int MessagesMoved { get; init; }

    /// <summary>
    /// Messages removed from the mailbox after their reports were stored.
    /// </summary>
    /// <remarks>
    /// Reported separately from the moved count rather than added to it. They
    /// are not the same event: one can be undone by dragging a folder, and the
    /// other is the run having thrown mail away on the operator's instruction.
    /// </remarks>
    public int MessagesDeleted { get; init; }
    public IReadOnlyList<IngestedReport> Reports { get; init; } = [];

    /// <summary>
    /// Messages that threw, or whose reports could not all be stored, and
    /// folders that could not be read. Kept per item so one failure is
    /// visible without having taken the run down.
    /// </summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>
    /// Every folder the run read, by display name, in the order it read them.
    /// </summary>
    /// <remarks>
    /// So a dry run shows which folders it actually reached. "Messages read"
    /// alone cannot tell a quiet folder from one that was never opened.
    /// </remarks>
    public IReadOnlyList<string> FoldersRead { get; init; } = [];

    /// <summary>True when the message cap was reached and a backlog remains.</summary>
    public bool StoppedEarly { get; init; }

    public int IngestedCount => Reports.Count(r => r.Outcome == IngestOutcome.Ingested);
    public int QuarantinedCount => Reports.Count(r => r.Outcome == IngestOutcome.Quarantined);
    public int DuplicateCount => Reports.Count(r => r.Outcome == IngestOutcome.Duplicate);
    public int UnrecognizedCount => Reports.Count(r => r.Outcome == IngestOutcome.Unrecognized);
    public int UnattributedCount => Reports.Count(r => r.Outcome == IngestOutcome.Unattributed);

    /// <summary>The distinct addresses unattributed reports were delivered to, most common first.</summary>
    public IReadOnlyList<string> UnattributedAddresses => Reports
        .Where(r => r.Outcome == IngestOutcome.Unattributed)
        .SelectMany(r => r.DeliveredTo)
        .GroupBy(a => a, StringComparer.OrdinalIgnoreCase)
        .OrderByDescending(g => g.Count())
        .Select(g => g.Key)
        .ToList();
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
    /// <summary>
    /// Stores what one message yielded, before that message is filed away.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Optional, and the reason it exists is a hole rather than a feature.
    /// Without it a run parses every message into a list, moves each one out
    /// of the source folder as it goes, and hands the whole list back to be
    /// stored after the run returns. Everything between the first move and the
    /// last save is a window in which the reports exist only in memory while
    /// their messages have already been filed - and the next run reads the
    /// source folder, not Processed, so anything lost there is never collected
    /// again.
    /// </para>
    /// <para>
    /// Returning false leaves the message where it is, so the next run picks
    /// it up. That is the safe direction: a message read twice is caught by
    /// the duplicate check, a message filed and never stored is gone.
    /// </para>
    /// </remarks>
    private readonly Func<IReadOnlyList<IngestedReport>, CancellationToken, Task<bool>>? _persist;

    public ReportIngestor(
        IMailboxClient mailbox,
        IngestOptions options,
        Func<string, string?>? resolveToken = null,
        Func<string, bool>? isAlreadyIngested = null,
        Func<IReadOnlyList<IngestedReport>, CancellationToken, Task<bool>>? persist = null)
    {
        _mailbox = mailbox ?? throw new ArgumentNullException(nameof(mailbox));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _resolveToken = resolveToken ?? (_ => null);
        _isAlreadyIngested = isAlreadyIngested ?? (_ => false);
        _persist = persist;
    }

    public async Task<IngestRunResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var reports = new List<IngestedReport>();
        var errors = new List<string>();
        var foldersRead = new List<string>();
        var read = 0;
        var moved = 0;
        var deleted = 0;
        var stoppedEarly = false;

        var processedId = await _mailbox.EnsureFolderAsync(_options.ProcessedFolder, cancellationToken).ConfigureAwait(false);
        var unrecognizedId = await _mailbox.EnsureFolderAsync(_options.UnrecognizedFolder, cancellationToken).ConfigureAwait(false);
        var quarantineId = await _mailbox.EnsureFolderAsync(_options.QuarantineFolder, cancellationToken).ConfigureAwait(false);

        // The source folders, each followed by the folders inside it. A mail
        // rule sorting by domain puts everything one level down, so reading
        // only the parent would find nothing and say nothing.
        List<MailFolder> folders;
        try
        {
            folders = await FoldersToReadAsync(
                new HashSet<string>(StringComparer.Ordinal) { processedId, unrecognizedId, quarantineId },
                errors, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            folders = [];
            stoppedEarly = true;
        }

        // The enumeration itself can throw on cancellation, so the whole loop
        // is wrapped. A canceled run has to RETURN what it already did: the
        // scheduled task is time-limited, so being cut off mid-backlog is the
        // normal case, not an exceptional one. Throwing here would discard
        // every report processed before the deadline and leave their messages
        // moved out of the source folder, so they would never be seen again.
        try
        {
        foreach (var folder in folders)
        {
        if (read >= _options.MaxMessages || stoppedEarly) { break; }
        foldersRead.Add(folder.Name);

        // By id, never by name again: see IMailboxClient.GetMessagesAsync.
        await foreach (var message in _mailbox.GetMessagesAsync(folder.Id, cancellationToken).ConfigureAwait(false))
        {
            if (cancellationToken.IsCancellationRequested) { stoppedEarly = true; break; }
            if (read >= _options.MaxMessages) { stoppedEarly = true; break; }
            read++;

            // Carry the folder through: a message read from DMARC\acme.com
            // knows which folder it came from even when the client did not
            // set it.
            var located = string.IsNullOrEmpty(message.FolderName)
                ? message with { FolderName = folder.Name }
                : message;

            List<IngestedReport> fromThisMessage;
            try
            {
                fromThisMessage = await ProcessMessageAsync(located, cancellationToken).ConfigureAwait(false);
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

            // Stored before the message is filed, not after the run ends.
            //
            // "In hand" used to mean parsed into a list, and the storing
            // happened once the whole run returned. Everything between the
            // first move and the last save was a window in which reports
            // existed only in memory while their messages had already been
            // moved out of the source folder - and the next run reads the
            // source folder, so a process killed in that window loses them for
            // good. A time-limited scheduled task being cut off mid-backlog is
            // described elsewhere in this file as the normal case.
            //
            // Failing to store leaves the message where it is. That is the
            // safe direction: a message read twice is caught by the duplicate
            // check, a message filed and never stored is gone.
            if (_persist is not null && fromThisMessage.Count > 0)
            {
                bool saved;
                string? why = null;
                try
                {
                    saved = await _persist(fromThisMessage, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    stoppedEarly = true;
                    break;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    saved = false;
                    why = ex.Message;
                }

                // Recorded whether the store threw or simply said no. Saying no
                // used to leave the message in place with nothing recorded at
                // all, so a run that had stored none of a message's reports
                // finished with no error and exited 0, and the next run did the
                // same again.
                if (!saved)
                {
                    errors.Add($"{message.Id}: {NotStored(fromThisMessage)} could not be stored, so it was left in place"
                             + (why is null ? "" : $": {why}"));
                    continue;
                }
            }

            var destination = ChooseDestination(fromThisMessage, processedId, unrecognizedId, quarantineId);
            if (destination is null) { continue; }

            // Deleting is only ever an alternative to filing in the processed
            // folder. Everything that lands anywhere else is something an
            // operator has to be able to look at afterwards, and the whole
            // point of those folders is that they survive.
            var delete = _options.DeleteProcessed != DeleteProcessed.Keep
                && string.Equals(destination, processedId, StringComparison.Ordinal);

            try
            {
                if (delete)
                {
                    await _mailbox
                        .DeleteMessageAsync(
                            message.Id, _options.DeleteProcessed == DeleteProcessed.Permanent, cancellationToken)
                        .ConfigureAwait(false);
                    deleted++;
                }
                else
                {
                    await _mailbox.MoveMessageAsync(message.Id, destination, cancellationToken).ConfigureAwait(false);
                    moved++;
                }
            }
            catch (OperationCanceledException)
            {
                stoppedEarly = true;
                break;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Survivable either way: the reports were already stored, and
                // the duplicate check stops them being counted twice when this
                // message is read again next run. A delete that failed leaves
                // the message in the source folder, which is the same place a
                // failed move leaves it.
                errors.Add($"{message.Id}: could not be {(delete ? "deleted" : "filed")}: {ex.Message}");
            }
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
            MessagesDeleted = deleted,
            Reports = reports,
            Errors = errors,
            FoldersRead = foldersRead,
            StoppedEarly = stoppedEarly,
        };
    }

    /// <summary>
    /// The folders to read, each followed by the folders directly inside it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every name is found once, up front, and read by id from then on. A
    /// name that is not there is recorded and skipped, never created, and the
    /// rest are still read: nine folders collected and one reported missing
    /// beats a run that stops at the first typo, and it beats a run that makes
    /// an empty folder of that name and reads it happily every hour.
    /// </para>
    /// <para>
    /// The folders this run files into are never read, even when named. Every
    /// message in them is one already dealt with, so reading one would file
    /// each of them again on every run - and spend the per-run message cap
    /// doing it while new reports waited.
    /// </para>
    /// </remarks>
    private async Task<List<MailFolder>> FoldersToReadAsync(
        HashSet<string> filedInto, List<string> errors, CancellationToken ct)
    {
        var folders = new List<MailFolder>();
        var taken = new HashSet<string>(StringComparer.Ordinal);

        var names = _options.SourceFolders
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            var folder = await _mailbox.FindFolderAsync(name, ct).ConfigureAwait(false);
            if (folder is null)
            {
                errors.Add($"There is no folder named '{name}' at the top of the mailbox, so it was not read. "
                         + "The name has to match exactly, backslashes and all; a shell or an environment file "
                         + "that treats a backslash as an escape will have removed it, so quote the name.");
                continue;
            }

            if (filedInto.Contains(folder.Id))
            {
                errors.Add($"'{name}' is where this run files mail, so it was not read as well: every message "
                         + "in it would be filed again on every run.");
                continue;
            }

            if (!taken.Add(folder.Id)) { continue; }
            folders.Add(folder);

            if (!_options.IncludeChildFolders) { continue; }

            try
            {
                foreach (var child in await _mailbox.GetChildFoldersAsync(folder.Id, ct).ConfigureAwait(false))
                {
                    if (filedInto.Contains(child.Id) || !taken.Add(child.Id)) { continue; }
                    folders.Add(child);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Not fatal: the parent folder is still read. But it is
                // recorded, because silently reading one folder when there are
                // twelve is exactly the failure this option exists to prevent.
                errors.Add($"Could not list folders inside '{name}': {ex.Message}");
            }
        }

        return folders;
    }

    /// <summary>Names the reports of one message that were due to be stored.</summary>
    private static string NotStored(List<IngestedReport> fromThisMessage)
    {
        var names = fromThisMessage
            .Where(r => r.Outcome == IngestOutcome.Ingested)
            .Select(r => r.FileName)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        return names.Count switch
        {
            0 => "its reports",
            1 => names[0],
            _ => string.Join(", ", names),
        };
    }

    /// <summary>
    /// Where a message goes once processed, or null to leave it where it is.
    /// Worst outcome wins: a message carrying one good report and one
    /// quarantined report is quarantined, so the thing worth looking at is not
    /// buried in the processed folder. An unattributed report stays put: moving
    /// it to the unrecognized folder would make a configuration mistake
    /// permanent, because nothing reads that folder again.
    /// </summary>
    /// <remarks>
    /// One unreadable report is enough to make the message unrecognized, not
    /// every one of them. A message with one good report and one this version
    /// could not read used to be filed as processed - which with --delete
    /// meant deleted, taking the only copy of the one that could not be read,
    /// and that is the one kind of mail the delete setting promises to keep.
    /// The good report is already stored by then, so nothing is lost by
    /// keeping the message where a person will look at it.
    /// </remarks>
    private static string? ChooseDestination(
        List<IngestedReport> reports, string processed, string unrecognized, string quarantine)
    {
        if (reports.Exists(r => r.Outcome == IngestOutcome.Quarantined)) { return quarantine; }
        if (reports.Exists(r => r.Outcome == IngestOutcome.Unattributed)) { return null; }
        if (reports.Count == 0) { return unrecognized; }
        if (reports.Exists(r => r.Outcome == IngestOutcome.Unrecognized)) { return unrecognized; }
        return processed;
    }

    private async Task<List<IngestedReport>> ProcessMessageAsync(MailMessage message, CancellationToken ct)
    {
        var results = new List<IngestedReport>();
        var attachments = await _mailbox.GetAttachmentsAsync(message.Id, ct).ConfigureAwait(false);
        var found = 0;

        foreach (var attachment in attachments)
        {
            ct.ThrowIfCancellationRequested();

            var budget = ExtractionBudget.ForMail();
            var fromThisAttachment = 0;

            foreach (var extracted in ReportAttachment.ExtractAll(attachment.Name, attachment.Content, budget))
            {
                fromThisAttachment++;
                results.Add(Handle(message, extracted));
            }

            found += fromThisAttachment;

            // What could not be read is recorded as unrecognized, with the
            // reason, rather than skipped. Skipped, a damaged attachment beside
            // a good report left the message looking fully processed - so it
            // was filed, or with --delete deleted, and the one copy of the
            // damaged report went with it. Reports cut off by the size limit
            // are the same case: taken as far as the limit, and the rest lost.
            foreach (var problem in budget.Unreadable)
            {
                results.Add(Unrecognized(message, attachment.Name, $"{attachment.Name}: {problem}"));
            }

            if (budget.Exhausted)
            {
                results.Add(Unrecognized(message, attachment.Name,
                    $"{attachment.Name}: too large to read in full. {fromThisAttachment} report(s) were taken from it "
                    + "and there may be more."));
            }
        }

        // Counted in reports found, not in results: an attachment that could
        // not be read adds a result, and says nothing about whether the report
        // is in the body instead.
        if (found == 0)
        {
            // Nothing in the attachments. For one report type that is the
            // normal case rather than a dead end: a DMARC failure report is a
            // multipart/report whose PARTS are the report, and Graph surfaces
            // the copy of the failed message as an itemAttachment, which
            // carries no bytes. A mailbox receiving failure reports filed
            // every one of them as unreadable junk while its attachment list
            // was empty and entirely correct.
            //
            // Asked for only here, so ordinary report mail never costs the
            // extra fetch, and a message that is simply not a report costs one
            // bounded read and is then filed exactly as before.
            var raw = await _mailbox.GetRawMessageAsync(message.Id, ct).ConfigureAwait(false);

            if (raw is { Length: > 0 })
            {
                foreach (var extracted in ReportAttachment.Extract(MessageFileName(message), raw))
                {
                    results.Add(Handle(message, extracted));
                }
            }
        }

        return results;
    }

    private IngestedReport Handle(MailMessage message, ExtractedReport extracted) => extracted.Kind switch
    {
        ReportKind.DmarcAggregate => HandleAggregate(message, extracted),
        ReportKind.TlsRpt => HandleTls(message, extracted),
        ReportKind.DmarcFailure => HandleFailure(message, extracted),
        _ => Unrecognized(message, extracted.FileName, "The attachment is not a report this version can read."),
    };

    /// <summary>
    /// A name for a report that came out of the message body rather than out
    /// of an attachment.
    /// </summary>
    /// <remarks>
    /// The file name is what an operator reads in the run log to find the
    /// thing again, and "(no attachment)" would send them looking for a file
    /// that never existed. The subject is what their mailbox shows.
    /// </remarks>
    private static string MessageFileName(MailMessage message) =>
        string.IsNullOrWhiteSpace(message.Subject) ? "(message body)" : message.Subject.Trim();

    private IngestedReport HandleAggregate(MailMessage message, ExtractedReport extracted)
    {
        var parsed = AggregateReportParser.Parse(extracted.Content);
        if (!parsed.Success)
        {
            return Unrecognized(message, extracted.FileName, parsed.Error);
        }

        var report = parsed.Report!;
        var attribution = Attribute(message, report.Policy.Domain);

        if (attribution.Outcome == AttributionOutcome.DomainMismatch)
        {
            return new IngestedReport
            {
                MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Quarantined,
                Kind = ReportKind.DmarcAggregate,
                Domain = attribution.Domain,
                ReportId = report.Metadata.ReportId,
                Reason = attribution.Reason,
            };
        }

        if (IsUnattributed(attribution))
        {
            return Unattributed(message, extracted.FileName, ReportKind.DmarcAggregate, report.Policy.Domain);
        }

        if (!attribution.ShouldIngest)
        {
            return Unrecognized(message, extracted.FileName, attribution.Reason);
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
            ArrivedAt = message.ReceivedAt,
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
            ArrivedAt = message.ReceivedAt,
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
            return Unrecognized(message, extracted.FileName, parsed.Error);
        }

        var report = parsed.Report!;
        var domain = report.Policies.Count > 0 ? report.Policies[0].Policy.Domain : "";
        var attribution = Attribute(message, domain);

        if (attribution.Outcome == AttributionOutcome.DomainMismatch)
        {
            return new IngestedReport
            {
                MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Quarantined,
                Kind = ReportKind.TlsRpt,
                Domain = attribution.Domain,
                ReportId = report.ReportId,
                Reason = attribution.Reason,
            };
        }

        if (IsUnattributed(attribution))
        {
            return Unattributed(message, extracted.FileName, ReportKind.TlsRpt, domain);
        }

        if (!attribution.ShouldIngest)
        {
            return Unrecognized(message, extracted.FileName, attribution.Reason);
        }

        // Only reachable through the shared address, which takes the domain
        // from the report and so accepts an empty one. Counted as ingested, a
        // report like this was handed to a store that declines it, left its
        // message in place, and was read, counted and declined again on every
        // run.
        if (ReportImporter.WhyTlsCannotBeFiled(report) is { } why)
        {
            return Unrecognized(message, extracted.FileName, why);
        }

        var key = $"tls|{attribution.Domain}|{report.OrganizationName}|{report.ReportId}";
        if (_isAlreadyIngested(key))
        {
            return new IngestedReport
            {
                MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
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
            ArrivedAt = message.ReceivedAt,
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
    /// A DMARC failure report: one message that failed, rather than a count of
    /// them.
    /// </summary>
    /// <remarks>
    /// Attributed exactly as the other two are, and that matters more here
    /// than anywhere else. These carry a real subject line and a real
    /// envelope, so a report filed under the wrong customer is not a wrong
    /// number on a dashboard - it is one client reading another client's mail.
    /// </remarks>
    private IngestedReport HandleFailure(MailMessage message, ExtractedReport extracted)
    {
        var parsed = ForensicReportParser.Parse(extracted.Content);
        if (!parsed.Success)
        {
            return Unrecognized(message, extracted.FileName, parsed.Error);
        }

        var report = parsed.Report!;
        var attribution = Attribute(message, report.Domain);

        // The reported message's own id, which is what a sender searches their
        // logs for, and the closest thing a failure report has to the report
        // id the other two carry.
        var reference = report.MessageId.Length > 0
            ? report.MessageId
            : $"{report.SourceIp}@{report.ArrivalDate?.ToString("O") ?? "unknown"}";

        if (attribution.Outcome == AttributionOutcome.DomainMismatch)
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                ArrivedAt = message.ReceivedAt,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Quarantined,
                Kind = ReportKind.DmarcFailure,
                Domain = attribution.Domain,
                ReportId = reference,
                Reason = attribution.Reason,
            };
        }

        if (IsUnattributed(attribution))
        {
            return Unattributed(message, extracted.FileName, ReportKind.DmarcFailure, report.Domain);
        }

        if (!attribution.ShouldIngest)
        {
            return Unrecognized(message, extracted.FileName, attribution.Reason);
        }

        var key = $"ruf|{attribution.Domain}|{reference}";
        if (_isAlreadyIngested(key))
        {
            return new IngestedReport
            {
                MessageId = message.Id,
                ArrivedAt = message.ReceivedAt,
                FileName = extracted.FileName,
                Outcome = IngestOutcome.Duplicate,
                Kind = ReportKind.DmarcFailure,
                Domain = attribution.Domain,
                ReportId = reference,
                Reason = "This report has already been ingested.",
            };
        }

        return new IngestedReport
        {
            MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
            FileName = extracted.FileName,
            Outcome = IngestOutcome.Ingested,
            Kind = ReportKind.DmarcFailure,
            Domain = attribution.Domain,
            ReportId = reference,
            Forensic = report,
            RawContent = extracted.Content,
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

        // The folder comes first, below only a per-domain address. An operator
        // whose mail rule sorted this into DMARC\acme.com has made a claim
        // about ownership that the sender could not influence, which is worth
        // more than the domain named inside a file anybody can send.
        var byFolder = FolderAttribution.Attribute(message.FolderName, reportDomain);
        if (byFolder is not null)
        {
            if (byFolder.Outcome == AttributionOutcome.FolderMismatch) { return byFolder; }
            best = byFolder;
        }

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

    private static IngestedReport Unrecognized(MailMessage message, string fileName, string reason) => new()
    {
        MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
        FileName = fileName,
        Outcome = IngestOutcome.Unrecognized,
        Reason = reason,
    };

    /// <summary>
    /// An address of no recognized shape. A per-domain address whose token
    /// resolves to nothing is different: that is the expected tail after a
    /// domain is removed, and filing it away is right.
    /// </summary>
    private static bool IsUnattributed(AttributionResult attribution) =>
        attribution.Outcome == AttributionOutcome.UnknownAddress && string.IsNullOrEmpty(attribution.Token);

    private static IngestedReport Unattributed(MailMessage message, string fileName, ReportKind kind, string claimedDomain) => new()
    {
        MessageId = message.Id,
            ArrivedAt = message.ReceivedAt,
        FileName = fileName,
        Outcome = IngestOutcome.Unattributed,
        Kind = kind,
        Domain = (claimedDomain ?? "").Trim().TrimEnd('.').ToLowerInvariant(),
        DeliveredTo = message.ToAddresses.Select(CleanAddress).Where(a => a.Length > 0).ToList(),
        Reason = "A genuine report, but delivered to an address that is neither the shared reporting address "
               + "nor a per-domain one. Left in the mailbox; set the shared address to the one it was sent to "
               + "and it is ingested on the next run.",
    };

    private static string CleanAddress(string address)
    {
        var cleaned = (address ?? "").Trim();
        var open = cleaned.LastIndexOf('<');
        var close = cleaned.LastIndexOf('>');
        if (open >= 0 && close > open) { cleaned = cleaned[(open + 1)..close].Trim(); }
        return cleaned;
    }
}
