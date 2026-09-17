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
/// where the behaviour worth testing lives: deduplication, attribution,
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
    IAsyncEnumerable<MailMessage> GetMessagesAsync(string folder, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<MailAttachment>> GetAttachmentsAsync(string messageId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves a message to another folder.
    /// </summary>
    /// <remarks>
    /// This is what makes progress durable. A run killed by its execution
    /// time limit leaves everything it already moved out of the way, so the
    /// next run resumes rather than starting again.
    /// </remarks>
    Task MoveMessageAsync(string messageId, string destinationFolderId, CancellationToken cancellationToken = default);

    /// <summary>Returns the id of a folder, creating it if it does not exist.</summary>
    Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default);

    /// <summary>
    /// The folders directly inside another one.
    /// </summary>
    /// <remarks>
    /// Needed because sorting reports into a folder per domain with a mail
    /// rule is the normal way an MSP organises this. Reading only the parent
    /// would ignore every report, and would do it silently.
    /// </remarks>
    Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderName, CancellationToken cancellationToken = default);
}
