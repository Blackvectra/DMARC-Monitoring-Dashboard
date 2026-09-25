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

    /// <summary>
    /// The whole message on the wire, for the ones that have one.
    /// </summary>
    /// <remarks>
    /// Only failure reports come from here, and only when the attachments held
    /// nothing - which is the point of the fallback and the thing worth
    /// asserting, so this is kept separate from the attachments rather than
    /// derived from them.
    /// </remarks>
    private readonly Dictionary<string, byte[]> _raw = new(StringComparer.Ordinal);

    /// <summary>Counts how many times each message's raw form was fetched.</summary>
    public Dictionary<string, int> RawFetches { get; } = new(StringComparer.Ordinal);

    public void Add(MailMessage message, params MailAttachment[] attachments)
    {
        _messages.Add(message);
        _attachments[message.Id] = [.. attachments];
    }

    /// <summary>A message whose report is in its body rather than attached to it.</summary>
    public void AddRaw(MailMessage message, string mime)
    {
        _messages.Add(message);
        _attachments[message.Id] = [];
        _raw[message.Id] = System.Text.Encoding.UTF8.GetBytes(mime);
    }

    public Task<byte[]?> GetRawMessageAsync(string messageId, CancellationToken cancellationToken = default)
    {
        RawFetches[messageId] = RawFetches.GetValueOrDefault(messageId) + 1;
        return Task.FromResult(_raw.TryGetValue(messageId, out var bytes) ? bytes : null);
    }

    public static MailAttachment Attachment(string name, string content) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = name,
        ContentType = "application/octet-stream",
        Size = content.Length,
        Content = System.Text.Encoding.UTF8.GetBytes(content),
    };

    /// <summary>
    /// Folders by id: each one's display name, and the id of the folder it
    /// sits in, or null at the top of the mailbox.
    /// </summary>
    /// <remarks>
    /// The ids are not the names, on purpose. The ingestor reads a folder by
    /// the id it was given, and a fake whose ids were its names could not
    /// tell that apart from looking the name up again - which is how every
    /// report a rule sorted into Inbox\acme.com once went uncollected. Inbox
    /// is the exception, as it is in Graph, which addresses it by name.
    /// </remarks>
    private readonly Dictionary<string, (string Name, string? ParentId)> _folders = new(StringComparer.Ordinal)
    {
        ["Inbox"] = ("Inbox", null),
    };

    /// <summary>
    /// Adds a folder, at the top of the mailbox or inside a top-level one,
    /// and returns its id. A message is put in it by setting its FolderName.
    /// </summary>
    public string AddFolder(string name, string? parent = null)
    {
        var parentId = parent is null ? null : TopLevel(parent)?.Id
            ?? throw new InvalidOperationException($"No top-level folder '{parent}' to put '{name}' in.");

        var id = $"folder-{_folders.Count}";
        _folders[id] = (name, parentId);
        return id;
    }

    private MailFolder? TopLevel(string name) => _folders
        .Where(f => f.Value.ParentId is null && string.Equals(f.Value.Name, name, StringComparison.OrdinalIgnoreCase))
        .Select(f => new MailFolder { Id = f.Key, Name = f.Value.Name })
        .FirstOrDefault();

    public async IAsyncEnumerable<MailMessage> GetMessagesAsync(
        string folderId,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Loud, like Graph answering 404: a folder read by anything but the
        // id it was given is a bug, not an empty folder.
        if (!_folders.TryGetValue(folderId, out var folder))
        {
            throw new InvalidOperationException($"No folder has the id '{folderId}'.");
        }

        foreach (var m in _messages.Where(m => !Moved.ContainsKey(m.Id) && FolderMatches(m, folder.Name)).OrderBy(m => m.ReceivedAt))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return m;
            await Task.Yield();
        }
    }

    /// <summary>A message with no folder set is in Inbox.</summary>
    private static bool FolderMatches(MailMessage m, string folderName) =>
        string.Equals(string.IsNullOrEmpty(m.FolderName) ? "Inbox" : m.FolderName, folderName, StringComparison.OrdinalIgnoreCase);

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

    public Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderId, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<MailFolder> result = _folders
            .Where(f => string.Equals(f.Value.ParentId, folderId, StringComparison.Ordinal))
            .Select(f => new MailFolder { Id = f.Key, Name = f.Value.Name })
            .ToList();
        return Task.FromResult(result);
    }

    /// <summary>Every name looked up to be read, found or not.</summary>
    public List<string> FoldersLookedUp { get; } = [];

    public Task<MailFolder?> FindFolderAsync(string folderName, CancellationToken cancellationToken = default)
    {
        FoldersLookedUp.Add(folderName);
        return Task.FromResult(TopLevel(folderName));
    }

    /// <summary>
    /// Records the folder as ensured and returns its id. One that is not there
    /// yet is made at the top of the mailbox with its name for an id, which is
    /// what the tests assert messages were moved to.
    /// </summary>
    public Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default)
    {
        if (!FoldersCreated.Contains(folderName)) { FoldersCreated.Add(folderName); }

        if (TopLevel(folderName) is { } existing) { return Task.FromResult(existing.Id); }

        _folders[folderName] = (folderName, null);
        return Task.FromResult(folderName);
    }
}
