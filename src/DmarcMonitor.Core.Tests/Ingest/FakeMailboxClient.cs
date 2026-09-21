using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// An in-memory mailbox, so the ingest pipeline can be exercised without a
/// tenant. Records what was moved where, which is how the durability
/// behavior is asserted.
/// </summary>
public sealed class FakeMailboxClient : IMailboxClient
{
    private readonly List<MailMessage> _messages = [];
    private readonly Dictionary<string, List<MailAttachment>> _attachments = new(StringComparer.Ordinal);

    /// <summary>messageId -> folder it was moved to.</summary>
    public Dictionary<string, string> Moved { get; } = new(StringComparer.Ordinal);

    /// <summary>Called as a message is filed, so a test can assert on ordering.</summary>
    public Action<string>? OnMove { get; set; }

    public List<string> FoldersCreated { get; } = [];

    /// <summary>Message ids whose attachment fetch should throw.</summary>
    public HashSet<string> FailAttachmentsFor { get; } = new(StringComparer.Ordinal);

    /// <summary>Message ids whose move should throw.</summary>
    public HashSet<string> FailMoveFor { get; } = new(StringComparer.Ordinal);

    /// <summary>Counts how many times each message's attachments were fetched.</summary>
    public Dictionary<string, int> AttachmentFetches { get; } = new(StringComparer.Ordinal);

    public void Add(MailMessage message, params MailAttachment[] attachments)
    {
        _messages.Add(message);
        _attachments[message.Id] = [.. attachments];
    }

    public static MailAttachment Attachment(string name, string content) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = name,
        ContentType = "application/octet-stream",
        Size = content.Length,
        Content = System.Text.Encoding.UTF8.GetBytes(content),
    };

    public async IAsyncEnumerable<MailMessage> GetMessagesAsync(
        string folder,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var m in _messages.Where(m => !Moved.ContainsKey(m.Id) && FolderMatches(m, folder)).OrderBy(m => m.ReceivedAt))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return m;
            await Task.Yield();
        }
    }

    /// <summary>A message with no folder set belongs to whatever folder is being read.</summary>
    private static bool FolderMatches(MailMessage m, string folder) =>
        string.IsNullOrEmpty(m.FolderName) || string.Equals(m.FolderName, folder, StringComparison.OrdinalIgnoreCase);

    public Task<IReadOnlyList<MailAttachment>> GetAttachmentsAsync(string messageId, CancellationToken cancellationToken = default)
    {
        AttachmentFetches[messageId] = AttachmentFetches.GetValueOrDefault(messageId) + 1;

        if (FailAttachmentsFor.Contains(messageId))
        {
            throw new InvalidOperationException("attachment fetch failed");
        }

        IReadOnlyList<MailAttachment> result = _attachments.TryGetValue(messageId, out var list) ? list : [];
        return Task.FromResult(result);
    }

    public Task MoveMessageAsync(string messageId, string destinationFolderId, CancellationToken cancellationToken = default)
    {
        if (FailMoveFor.Contains(messageId))
        {
            throw new InvalidOperationException("move failed");
        }
        OnMove?.Invoke(messageId);
        Moved[messageId] = destinationFolderId;
        return Task.CompletedTask;
    }

    /// <summary>Message id to whether it was deleted permanently.</summary>
    public Dictionary<string, bool> Deleted { get; } = [];

    /// <summary>Ids whose delete should throw, for the survivable-failure case.</summary>
    public HashSet<string> FailDeleteFor { get; } = [];

    public Task DeleteMessageAsync(string messageId, bool permanent, CancellationToken cancellationToken = default)
    {
        if (FailDeleteFor.Contains(messageId))
        {
            throw new InvalidOperationException("delete failed");
        }

        Deleted[messageId] = permanent;
        return Task.CompletedTask;
    }

    /// <summary>Folders inside a parent, keyed by parent name.</summary>
    public Dictionary<string, List<MailFolder>> ChildFolders { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderName, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<MailFolder> result = ChildFolders.TryGetValue(folderName, out var list) ? list : [];
        return Task.FromResult(result);
    }

    public Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default)
    {
        if (!FoldersCreated.Contains(folderName)) { FoldersCreated.Add(folderName); }
        return Task.FromResult(folderName);
    }
}
