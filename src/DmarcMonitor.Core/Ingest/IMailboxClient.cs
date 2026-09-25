namespace DmarcMonitor.Core.Ingest;

/// <summary>A message sitting in the reporting mailbox.</summary>
public sealed record MailMessage
{
    public required string Id { get; init; }
    public string Subject { get; init; } = "";
    public string From { get; init; } = "";

    /// <summary>
    /// Every address the message was addressed to.
    /// </summary>
    /// <remarks>
    /// This is what per-domain attribution rests on, so it is a list rather
    /// than a single value: a receiver that sends to several addresses at
    /// once would otherwise have all but one silently dropped.
    /// </remarks>
    public IReadOnlyList<string> ToAddresses { get; init; } = [];

    public DateTimeOffset ReceivedAt { get; init; }
    public bool HasAttachments { get; init; }

    /// <summary>
    /// The folder this message was read from.
    /// </summary>
    /// <remarks>
    /// Attribution uses it. An MSP who sorts reports with a mail rule into
    /// DMARC\acme.com has made a claim about which domain those reports belong
    /// to, and that claim was made by the operator rather than by whoever sent
    /// the mail, so it is worth as much as a per-domain address and more than
    /// the XML alone.
    /// </remarks>
    public string FolderName { get; init; } = "";
}

/// <summary>A mail folder.</summary>
public sealed record MailFolder
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public int ChildFolderCount { get; init; }
    public int TotalItemCount { get; init; }
}

public sealed record MailAttachment
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string ContentType { get; init; } = "";
    public long Size { get; init; }
    public required byte[] Content { get; init; }
}

/// <summary>
/// The mailbox operations ingest needs.
///
/// An interface rather than a Graph client directly, because the pipeline is
/// where the behavior worth testing lives: deduplication, attribution,
/// surviving a malformed message, and making progress through a backlog. None
/// of that should need a tenant to exercise.
/// </summary>
public interface IMailboxClient
{
    /// <summary>
    /// Messages in a folder, oldest first.
    /// </summary>
    /// <remarks>
    /// Oldest first on purpose. A first run against a mailbox holding months
    /// of reports will not finish inside one scheduled window, so it has to
    /// chew through the backlog in a stable order. Newest-first would keep
    /// re-processing the same recent mail and never reach the bottom.
    /// </remarks>
    /// <param name="folderId">
    /// The folder's id, as <see cref="FindFolderAsync"/> or
    /// <see cref="GetChildFoldersAsync"/> gave it - never its display name.
    /// Reading by name meant looking the name up again, and a lookup that
    /// found nothing created an empty folder of that name and read that
    /// instead, so a folder that was there but not where the lookup looked
    /// was never collected, with nothing said.
    /// </param>
    IAsyncEnumerable<MailMessage> GetMessagesAsync(string folderId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<MailAttachment>> GetAttachmentsAsync(string messageId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The whole message as it arrived on the wire, or null when it cannot be
    /// had.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needed because one report type is not an attachment. A DMARC failure
    /// report (RFC 6591) is a <c>multipart/report</c> whose parts ARE the
    /// report: a feedback part holding the fields, and a copy of the message
    /// that failed. Graph surfaces the second of those as an itemAttachment,
    /// which carries no bytes, and sometimes surfaces neither - so a mailbox
    /// receiving failure reports filed every one of them as unreadable junk
    /// while the attachment list was empty and correct.
    /// </para>
    /// <para>
    /// Only asked for when the attachments yielded nothing, so ordinary report
    /// mail costs no extra call. Null rather than throwing: a message whose
    /// raw form cannot be fetched is one more message that is not a report,
    /// which is a normal thing for a mailbox to contain.
    /// </para>
    /// </remarks>
    Task<byte[]?> GetRawMessageAsync(string messageId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves a message to another folder.
    /// </summary>
    /// <remarks>
    /// This is what makes progress durable. A run killed by its execution
    /// time limit leaves everything it already moved out of the way, so the
    /// next run resumes rather than starting again.
    /// </remarks>
    Task MoveMessageAsync(string messageId, string destinationFolderId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a message.
    /// </summary>
    /// <param name="permanent">
    /// False puts it in Deleted Items, where a person can get it back and
    /// where it still counts against the mailbox quota. True removes it from
    /// the mailbox proper; in Exchange Online it is recoverable for the
    /// tenant's retention period from Recoverable Items, which has a quota of
    /// its own, so this is the one that actually gives the space back.
    /// </param>
    /// <remarks>
    /// Only ever called for a message whose reports are already in the
    /// database. See <see cref="DeleteProcessed"/> for why nothing else is
    /// eligible, and why this is off unless an operator asks for it.
    /// </remarks>
    Task DeleteMessageAsync(string messageId, bool permanent, CancellationToken cancellationToken = default);

    /// <summary>Returns the id of a folder, creating it if it does not exist.</summary>
    /// <remarks>
    /// For the folders a run files mail into. Never for a folder to read:
    /// see <see cref="FindFolderAsync"/>.
    /// </remarks>
    Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default);

    /// <summary>
    /// A folder at the top of the mailbox, beside Inbox, found by its exact
    /// display name - or a well-known one such as Inbox - or null when there
    /// is no such folder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Never creates anything, which is the difference from
    /// <see cref="EnsureFolderAsync"/> and the reason this exists. A folder
    /// named to be read that is not there is a mistake to report: creating an
    /// empty one and reading it looks exactly like a quiet mailbox, and a
    /// --dry-run doing it writes into the live mailbox.
    /// </para>
    /// <para>
    /// The name is matched whole. A backslash in it is part of the name and
    /// not a path: the mailbox this was built for has Outlook rules filing
    /// reports into folders literally called <c>DMARC\example.org</c>.
    /// </para>
    /// </remarks>
    Task<MailFolder?> FindFolderAsync(string folderName, CancellationToken cancellationToken = default);

    /// <summary>
    /// The folders directly inside another one.
    /// </summary>
    /// <remarks>
    /// Needed because sorting reports into a folder per domain with a mail
    /// rule is the normal way an MSP organizes this. Reading only the parent
    /// would ignore every report, and would do it silently.
    /// </remarks>
    /// <param name="folderId">The parent's id, as <see cref="FindFolderAsync"/> gave it.</param>
    Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderId, CancellationToken cancellationToken = default);
}
