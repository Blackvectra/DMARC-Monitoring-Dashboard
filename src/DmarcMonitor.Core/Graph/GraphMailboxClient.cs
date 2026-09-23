using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Graph;

/// <summary>
/// Reads the reporting mailbox through Microsoft Graph.
///
/// Deliberately thin: everything worth testing lives in ReportIngestor, which
/// depends on IMailboxClient rather than on this. What is here is the bits
/// that only Graph gets to decide — paging, throttling, the attachment
/// content endpoint, and turning a failure into a sentence that names a cause.
///
/// The HttpClient is injected rather than constructed, so the paging, error
/// translation and attachment handling can all be exercised against a stub
/// without a tenant.
/// </summary>
public sealed class GraphMailboxClient : IMailboxClient
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private readonly HttpClient _http;
    private readonly string _mailbox;

    /// <summary>Folder display name to id, so a folder is looked up once per run.</summary>
    private readonly Dictionary<string, string> _folderCache = new(StringComparer.OrdinalIgnoreCase);

    public GraphMailboxClient(HttpClient httpClient, string mailboxAddress)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(mailboxAddress);

        _http = httpClient;
        _mailbox = mailboxAddress.Trim();
    }

    private string UserBase => $"{GraphBase}/users/{Uri.EscapeDataString(_mailbox)}";

    public async IAsyncEnumerable<MailMessage> GetMessagesAsync(
        string folder,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var folderId = await EnsureFolderAsync(folder, cancellationToken).ConfigureAwait(false);

        // Oldest first, matching the contract on IMailboxClient: a backlog has
        // to be worked through in a stable order rather than revisited.
        //
        // hasAttachments is NOT filtered server-side. Graph's filter is
        // unreliable for messages whose only attachment is inline, and a
        // report silently excluded by the server is invisible: it stays in the
        // inbox forever and nothing reports it as skipped.
        var uri = $"{UserBase}/mailFolders/{Uri.EscapeDataString(folderId)}/messages"
                + "?$top=50"
                + "&$orderby=receivedDateTime%20asc"
                + "&$select=id,subject,from,toRecipients,receivedDateTime,hasAttachments";

        while (!string.IsNullOrEmpty(uri))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var doc = await GetJsonAsync(uri, cancellationToken).ConfigureAwait(false);
            var root = doc.RootElement;

            if (root.TryGetProperty("value", out var values) && values.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in values.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var message = ReadMessage(item);
                    if (message is not null) { yield return message; }
                }
            }

            uri = root.TryGetProperty("@odata.nextLink", out var next) && next.ValueKind == JsonValueKind.String
                ? next.GetString() ?? ""
                : "";
        }
    }

    public async Task<IReadOnlyList<MailAttachment>> GetAttachmentsAsync(
        string messageId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        var uri = $"{UserBase}/messages/{Uri.EscapeDataString(messageId)}/attachments"
                + "?$select=id,name,contentType,size";

        var results = new List<MailAttachment>();

        while (!string.IsNullOrEmpty(uri))
        {
            using var doc = await GetJsonAsync(uri, cancellationToken).ConfigureAwait(false);
            var root = doc.RootElement;

            if (root.TryGetProperty("value", out var values) && values.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in values.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var type = Str(item, "@odata.type");

                    // Only file attachments carry bytes. An itemAttachment is a
                    // forwarded message and a referenceAttachment is a link to
                    // cloud storage; asking either for $value fails, and a
                    // failure here would take down the whole message.
                    if (!string.IsNullOrEmpty(type) &&
                        !type.Contains("fileAttachment", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var id = Str(item, "id");
                    if (string.IsNullOrEmpty(id)) { continue; }

                    var content = await GetAttachmentBytesAsync(messageId, id, cancellationToken).ConfigureAwait(false);

                    results.Add(new MailAttachment
                    {
                        Id = id,
                        Name = Str(item, "name"),
                        ContentType = Str(item, "contentType"),
                        Size = Num(item, "size"),
                        Content = content,
                    });
                }
            }

            uri = root.TryGetProperty("@odata.nextLink", out var next) && next.ValueKind == JsonValueKind.String
                ? next.GetString() ?? ""
                : "";
        }

        return results;
    }

    /// <summary>
    /// How much of one raw message is read.
    /// </summary>
    /// <remarks>
    /// A failure report is a few kilobytes: some fields and a header block. A
    /// megabyte is room for a receiver that attached the whole original mail
    /// with a photograph in it, and a firm stop before a mailbox full of
    /// holiday pictures is read into memory one message at a time looking for
    /// reports that are not there.
    /// </remarks>
    public const int MaxRawMessageBytes = 1024 * 1024;

    /// <inheritdoc />
    public async Task<byte[]?> GetRawMessageAsync(
        string messageId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        var uri = $"{UserBase}/messages/{Uri.EscapeDataString(messageId)}/$value";

        using var response = await _http
            .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        // Null rather than an exception, deliberately. This is only ever
        // reached for a message whose attachments held no report, so every
        // failure here means "still not a report" - and throwing would turn a
        // mailbox containing one odd message into a run that stops.
        if (!response.IsSuccessStatusCode) { return null; }

        if (response.Content.Headers.ContentLength > MaxRawMessageBytes) { return null; }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();

        // Copied with a bound rather than ReadAsByteArrayAsync: Content-Length
        // is what the server claims, and a response without one would
        // otherwise be read until the mailbox ran the process out of memory.
        var chunk = new byte[64 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxRawMessageBytes) { return null; }
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    public async Task MoveMessageAsync(
        string messageId, string destinationFolderId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationFolderId);

        var uri = $"{UserBase}/messages/{Uri.EscapeDataString(messageId)}/move";

        using var response = await _http
            .PostAsJsonAsync(uri, new { destinationId = destinationFolderId }, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var body = await SafeReadAsync(response, cancellationToken).ConfigureAwait(false);
            throw GraphError.Translate(response.StatusCode, body, _mailbox);
        }
    }

    /// <summary>
    /// Deletes a message, either to Deleted Items or out of the mailbox.
    /// </summary>
    /// <remarks>
    /// Two different Graph operations rather than one with a flag. DELETE on a
    /// message is a soft delete: Outlook shows it in Deleted Items and it
    /// still occupies the mailbox quota, which is usually the thing the
    /// operator was trying to reclaim. permanentDelete moves it to Recoverable
    /// Items, whose quota is separate, so that is the one that gives the space
    /// back - and it is still recoverable for the tenant's retention period,
    /// which is why it is offered at all rather than being considered too
    /// sharp to ship.
    /// </remarks>
    public async Task DeleteMessageAsync(
        string messageId, bool permanent, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        var id = Uri.EscapeDataString(messageId);

        using var response = permanent
            ? await _http.PostAsync(
                new Uri($"{UserBase}/messages/{id}/permanentDelete"), content: null, cancellationToken)
                .ConfigureAwait(false)
            : await _http.DeleteAsync(new Uri($"{UserBase}/messages/{id}"), cancellationToken)
                .ConfigureAwait(false);

        // A message that is already gone is the outcome that was wanted. It
        // happens when a run is cut off between the delete and recording it,
        // and treating it as a failure would fill the log with errors about
        // work that succeeded.
        if (response.StatusCode == HttpStatusCode.NotFound) { return; }

        if (!response.IsSuccessStatusCode)
        {
            var body = await SafeReadAsync(response, cancellationToken).ConfigureAwait(false);
            throw GraphError.Translate(response.StatusCode, body, _mailbox);
        }
    }

    public async Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderName);

        if (_folderCache.TryGetValue(folderName, out var cached)) { return cached; }

        // Inbox and friends are addressable by name, so they need no lookup
        // and must not be "created".
        if (IsWellKnownFolder(folderName))
        {
            _folderCache[folderName] = folderName;
            return folderName;
        }

        var existing = await FindFolderAsync(folderName, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            _folderCache[folderName] = existing;
            return existing;
        }

        var created = await CreateFolderAsync(folderName, cancellationToken).ConfigureAwait(false);
        _folderCache[folderName] = created;
        return created;
    }

    public async Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(
        string folderName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderName);

        var folderId = await EnsureFolderAsync(folderName, cancellationToken).ConfigureAwait(false);
        var uri = $"{UserBase}/mailFolders/{Uri.EscapeDataString(folderId)}/childFolders"
                + "?$select=id,displayName,childFolderCount,totalItemCount&$top=100";

        var results = new List<MailFolder>();

        while (!string.IsNullOrEmpty(uri))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var doc = await GetJsonAsync(uri, cancellationToken).ConfigureAwait(false);
            var root = doc.RootElement;

            if (root.TryGetProperty("value", out var values) && values.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in values.EnumerateArray())
                {
                    var id = Str(item, "id");
                    var name = Str(item, "displayName");
                    if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name)) { continue; }

                    // Remembered by id, so reading this folder next finds it.
                    // The ingestor asks for a child by name, and the name was
                    // looked up again among ROOT folders only - where a folder
                    // one level down is not - found nothing, and then CREATED
                    // an empty top-level folder of that name and read it. So
                    // every report a mail rule had sorted into Inbox\acme.com
                    // was never collected, silently, and a --dry-run wrote
                    // folders into the live mailbox doing it.
                    _folderCache[name] = id;

                    results.Add(new MailFolder
                    {
                        Id = id,
                        Name = name,
                        ChildFolderCount = (int)Num(item, "childFolderCount"),
                        TotalItemCount = (int)Num(item, "totalItemCount"),
                    });
                }
            }

            uri = root.TryGetProperty("@odata.nextLink", out var next) && next.ValueKind == JsonValueKind.String
                ? next.GetString() ?? ""
                : "";
        }

        return results;
    }

    private async Task<string?> FindFolderAsync(string folderName, CancellationToken ct)
    {
        // OData string literals escape a single quote by doubling it. Without
        // this, a folder name containing an apostrophe produces a malformed
        // filter that Graph rejects as a bad request.
        var literal = folderName.Replace("'", "''", StringComparison.Ordinal);
        var uri = $"{UserBase}/mailFolders?$filter=displayName%20eq%20'{Uri.EscapeDataString(literal)}'&$select=id,displayName&$top=10";

        using var doc = await GetJsonAsync(uri, ct).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("value", out var values) || values.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var item in values.EnumerateArray())
        {
            // Compare the name back rather than trusting the filter: Graph's
            // comparison is case-insensitive, and taking the first result
            // could return a differently-cased folder.
            if (string.Equals(Str(item, "displayName"), folderName, StringComparison.OrdinalIgnoreCase))
            {
                var id = Str(item, "id");
                if (!string.IsNullOrEmpty(id)) { return id; }
            }
        }
        return null;
    }

    private async Task<string> CreateFolderAsync(string folderName, CancellationToken ct)
    {
        var uri = $"{UserBase}/mailFolders";

        using var response = await _http
            .PostAsJsonAsync(uri, new { displayName = folderName }, ct)
            .ConfigureAwait(false);

        var body = await SafeReadAsync(response, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // Another run may have created it in between. Losing that race is
            // normal when two runs overlap and is not worth failing over.
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                var found = await FindFolderAsync(folderName, ct).ConfigureAwait(false);
                if (found is not null) { return found; }
            }
            throw GraphError.Translate(response.StatusCode, body, _mailbox);
        }

        using var doc = ParseOrThrow(body);
        var id = Str(doc.RootElement, "id");
        if (string.IsNullOrEmpty(id))
        {
            throw new GraphException(response.StatusCode, "",
                $"Microsoft Graph created the folder '{folderName}' but did not return its id.");
        }
        return id;
    }

    private async Task<byte[]> GetAttachmentBytesAsync(string messageId, string attachmentId, CancellationToken ct)
    {
        var uri = $"{UserBase}/messages/{Uri.EscapeDataString(messageId)}"
                + $"/attachments/{Uri.EscapeDataString(attachmentId)}/$value";

        using var response = await _http.GetAsync(uri, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var body = await SafeReadAsync(response, ct).ConfigureAwait(false);
            throw GraphError.Translate(response.StatusCode, body, _mailbox);
        }

        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    private async Task<JsonDocument> GetJsonAsync(string uri, CancellationToken ct)
    {
        using var response = await _http.GetAsync(uri, ct).ConfigureAwait(false);
        var body = await SafeReadAsync(response, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw GraphError.Translate(response.StatusCode, body, _mailbox);
        }

        return ParseOrThrow(body);
    }

    private static JsonDocument ParseOrThrow(string body)
    {
        try
        {
            return JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
        }
        catch (JsonException ex)
        {
            // Almost always a proxy or captive portal returning HTML where
            // JSON was expected. Saying so beats a bare parse error.
            throw new GraphException(HttpStatusCode.OK, "",
                "Microsoft Graph returned a response that is not JSON. This usually means something between this "
                + "machine and Graph is intercepting the request, such as a proxy or a captive portal.", ex);
        }
    }

    private static async Task<string> SafeReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try { return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false); }
        catch (HttpRequestException) { return ""; }
        catch (IOException) { return ""; }
    }

    /// <summary>
    /// Reads one message, or null if it has no id and so cannot be acted on.
    /// </summary>
    internal static MailMessage? ReadMessage(JsonElement item)
    {
        var id = Str(item, "id");
        if (string.IsNullOrEmpty(id)) { return null; }

        var to = new List<string>();
        if (item.TryGetProperty("toRecipients", out var recipients) && recipients.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in recipients.EnumerateArray())
            {
                if (r.TryGetProperty("emailAddress", out var ea) && ea.ValueKind == JsonValueKind.Object)
                {
                    var address = Str(ea, "address");
                    if (!string.IsNullOrWhiteSpace(address)) { to.Add(address); }
                }
            }
        }

        var from = "";
        if (item.TryGetProperty("from", out var f) && f.ValueKind == JsonValueKind.Object &&
            f.TryGetProperty("emailAddress", out var fea) && fea.ValueKind == JsonValueKind.Object)
        {
            from = Str(fea, "address");
        }

        var received = DateTimeOffset.MinValue;
        var raw = Str(item, "receivedDateTime");
        if (!string.IsNullOrEmpty(raw) &&
            DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            received = parsed;
        }

        return new MailMessage
        {
            Id = id,
            Subject = Str(item, "subject"),
            From = from,
            ToAddresses = to,
            ReceivedAt = received,
            HasAttachments = item.TryGetProperty("hasAttachments", out var ha) && ha.ValueKind == JsonValueKind.True,
        };
    }

    internal static bool IsWellKnownFolder(string name) => name.ToLowerInvariant() switch
    {
        "inbox" or "archive" or "drafts" or "sentitems" or "deleteditems" or
        "junkemail" or "outbox" or "recoverableitemsdeletions" or "msgfolderroot" => true,
        _ => false,
    };

    private static string Str(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object) { return ""; }
        if (!parent.TryGetProperty(name, out var el)) { return ""; }
        return el.ValueKind == JsonValueKind.String ? el.GetString()?.Trim() ?? "" : "";
    }

    private static long Num(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object) { return 0; }
        if (!parent.TryGetProperty(name, out var el)) { return 0; }
        return el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var n) ? n : 0;
    }
}
