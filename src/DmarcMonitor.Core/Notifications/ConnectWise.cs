using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DmarcMonitor.Core.Findings;
using System.Text.Json.Serialization;

namespace DmarcMonitor.Core.Notifications;

/// <summary>
/// What is kept in the secret store for a ConnectWise destination. All of it,
/// the public half included: together the four are the credential.
/// </summary>
/// <param name="Site">The API base address, ending in the version path.</param>
internal sealed record ConnectWiseCredential(string Site, string CompanyId, string PublicKey, string PrivateKey, string ClientId);

/// <summary>
/// What is not secret about a ConnectWise destination, kept in the database
/// beside the pointer to what is: where tickets go and what they are marked.
/// </summary>
/// <param name="Board">The service board tickets are created on. Required by the API.</param>
/// <param name="Status">A status name on that board, or null for the board's default.</param>
/// <param name="PriorityCritical">The priority name a critical finding gets, or null for the default.</param>
/// <param name="PriorityWarning">The priority name a warning gets, or null for the default.</param>
public sealed record ConnectWiseSettings(
    string Board, string? Status = null, string? PriorityCritical = null, string? PriorityWarning = null)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static ConnectWiseSettings? FromJson(string? json) =>
        string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<ConnectWiseSettings>(json, Json);

    /// <summary>The priority a finding of this severity is filed at, or null for the board's default.</summary>
    public string? PriorityFor(string? severity) => severity switch
    {
        "critical" => PriorityCritical,
        _ => PriorityWarning,
    };
}

/// <summary>A company in ConnectWise, as much as is needed to pick one.</summary>
public sealed record ConnectWiseCompany(int Id, string Identifier, string Name);

/// <summary>A ticket in ConnectWise, as much as is needed to add to it or leave it alone.</summary>
public sealed record ConnectWiseTicket(int Id, string Summary, bool Closed, string? Status);

/// <summary>A ticket to create.</summary>
internal sealed record NewTicket(string Summary, string Board, int CompanyId, string? Status, string? Priority, string Description);

/// <summary>ConnectWise answered with something other than success, or did not answer.</summary>
public sealed class ConnectWiseException(string message, int? status = null) : Exception(message)
{
    public int? Status { get; } = status;
}

/// <summary>
/// The few calls into the ConnectWise PSA REST API this product makes.
/// </summary>
/// <remarks>
/// <para>
/// Authentication as ConnectWise documents it: HTTP Basic with
/// <c>companyId+publicKey:privateKey</c>, and a <c>clientId</c> header
/// carrying the id registered for this integration at developer.connectwise.com.
/// A request without the header is refused with a 401 whatever the keys say.
/// </para>
/// <para>
/// Every failure is a <see cref="ConnectWiseException"/> with the status and a
/// piece of what ConnectWise said, which is usually the whole diagnosis. The
/// caller treats any of them as the run stopping, so what was not filed waits
/// for the next run rather than being filed out of order.
/// </para>
/// </remarks>
internal sealed class ConnectWiseClient
{
    /// <summary>The REST API's path on any ConnectWise site, hosted or on premises.</summary>
    public const string ApiPath = "v4_6_release/apis/3.0/";

    /// <summary>ConnectWise's limit on a ticket summary.</summary>
    public const int SummaryLimit = 100;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly Uri _base;
    private readonly string _authorization;
    private readonly string _clientId;

    public ConnectWiseClient(HttpClient http, ConnectWiseCredential credential)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(credential);

        _http = http;
        _base = BaseFor(credential.Site);
        _authorization = AuthorizationFor(credential);
        _clientId = credential.ClientId;
    }

    /// <summary>
    /// The API's base address for a site: the host as given, with the version
    /// path added when the site was given without one.
    /// </summary>
    /// <exception cref="ArgumentException">Not an https address (or http to this machine, for trying out).</exception>
    public static Uri BaseFor(string site)
    {
        var uri = WebhookStore.ParseAddress(site);
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.Length == 0) { path = "/" + ApiPath.TrimEnd('/'); }
        return new UriBuilder(uri.Scheme, uri.Host, uri.Port, path + "/").Uri;
    }

    /// <summary>The Basic credential ConnectWise expects: company+public:private, Base64.</summary>
    public static string AuthorizationFor(ConnectWiseCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{credential.CompanyId}+{credential.PublicKey}:{credential.PrivateKey}"));
    }

    /// <summary>
    /// Proves the credential works and the API member may read companies,
    /// which every delivery needs, without changing anything.
    /// </summary>
    public async Task CheckAsync(CancellationToken ct)
    {
        using var answer = await SendAsync(HttpMethod.Get, "company/companies?pageSize=1&fields=id", null, ct).ConfigureAwait(false);
    }

    public async Task<bool> BoardExistsAsync(string name, CancellationToken ct)
    {
        using var answer = await SendAsync(HttpMethod.Get,
            $"service/boards?conditions={Uri.EscapeDataString($"name={Quote(name)}")}&fields=id,name&pageSize=1", null, ct).ConfigureAwait(false);
        return answer.RootElement.ValueKind == JsonValueKind.Array && answer.RootElement.GetArrayLength() > 0;
    }

    /// <summary>Companies whose name or identifier contains the text, at most 25, for a person to pick from.</summary>
    public async Task<IReadOnlyList<ConnectWiseCompany>> SearchCompaniesAsync(string text, CancellationToken ct)
    {
        var conditions = $"name contains {Quote(text)} or identifier contains {Quote(text)}";
        using var answer = await SendAsync(HttpMethod.Get,
            $"company/companies?conditions={Uri.EscapeDataString(conditions)}&fields=id,identifier,name&pageSize=25&orderBy=name",
            null, ct).ConfigureAwait(false);

        var found = new List<ConnectWiseCompany>();
        foreach (var company in answer.RootElement.EnumerateArray())
        {
            found.Add(new ConnectWiseCompany(
                company.GetProperty("id").GetInt32(),
                Text(company, "identifier") ?? "",
                Text(company, "name") ?? ""));
        }
        return found;
    }

    /// <summary>The ticket, or null when ConnectWise no longer has it.</summary>
    public async Task<ConnectWiseTicket?> GetTicketAsync(int id, CancellationToken ct)
    {
        try
        {
            using var answer = await SendAsync(HttpMethod.Get,
                $"service/tickets/{id.ToString(CultureInfo.InvariantCulture)}?fields=id,summary,closedFlag,status", null, ct).ConfigureAwait(false);
            return Ticket(answer.RootElement);
        }
        catch (ConnectWiseException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    /// <summary>
    /// The ticket whose summary carries the marker, or null: how a create whose
    /// answer was lost on the way back is found again rather than repeated.
    /// </summary>
    public async Task<ConnectWiseTicket?> FindTicketAsync(string marker, CancellationToken ct)
    {
        using var answer = await SendAsync(HttpMethod.Get,
            $"service/tickets?conditions={Uri.EscapeDataString($"summary contains {Quote(marker)}")}&fields=id,summary,closedFlag,status&pageSize=1",
            null, ct).ConfigureAwait(false);
        return answer.RootElement.ValueKind == JsonValueKind.Array && answer.RootElement.GetArrayLength() > 0
            ? Ticket(answer.RootElement[0])
            : null;
    }

    public async Task<ConnectWiseTicket> CreateTicketAsync(NewTicket ticket, CancellationToken ct)
    {
        var body = JsonSerializer.Serialize(new
        {
            summary = ticket.Summary,
            board = new { name = ticket.Board },
            company = new { id = ticket.CompanyId },
            status = ticket.Status is null ? null : new { name = ticket.Status },
            priority = ticket.Priority is null ? null : new { name = ticket.Priority },
            initialDescription = ticket.Description,
        }, Json);

        using var answer = await SendAsync(HttpMethod.Post, "service/tickets", body, ct).ConfigureAwait(false);
        return Ticket(answer.RootElement);
    }

    /// <summary>A note on the ticket, in its discussion, visible to the customer as the ticket is.</summary>
    public async Task AddNoteAsync(int ticketId, string text, CancellationToken ct)
    {
        var body = JsonSerializer.Serialize(new
        {
            text,
            detailDescriptionFlag = true,
            internalAnalysisFlag = false,
            resolutionFlag = false,
        }, Json);

        using var answer = await SendAsync(HttpMethod.Post,
            $"service/tickets/{ticketId.ToString(CultureInfo.InvariantCulture)}/notes", body, ct).ConfigureAwait(false);
    }

    private async Task<JsonDocument> SendAsync(HttpMethod method, string relative, string? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(_base, relative));
        request.Headers.TryAddWithoutValidation("Authorization", "Basic " + _authorization);
        request.Headers.TryAddWithoutValidation("clientId", _clientId);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ConnectWiseException($"ConnectWise could not be reached: {ex.Message}");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ConnectWiseException($"ConnectWise gave no answer within {WebhookNotifier.RequestTimeout.TotalSeconds:0} seconds.");
        }

        using (response)
        {
            var said = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var status = (int)response.StatusCode;

            if (!response.IsSuccessStatusCode)
            {
                throw new ConnectWiseException($"ConnectWise answered {status} {response.ReasonPhrase}: {Explain(status, said)}", status);
            }

            try
            {
                return string.IsNullOrWhiteSpace(said) ? JsonDocument.Parse("{}") : JsonDocument.Parse(said);
            }
            catch (JsonException)
            {
                throw new ConnectWiseException($"ConnectWise answered {status} with something that is not JSON.", status);
            }
        }
    }

    /// <summary>The useful part of an error, plus what it usually means.</summary>
    private static string Explain(int status, string said)
    {
        var message = said.Trim();
        try
        {
            using var error = JsonDocument.Parse(message);
            if (error.RootElement.ValueKind == JsonValueKind.Object)
            {
                message = Text(error.RootElement, "message") ?? message;
                if (error.RootElement.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
                {
                    message += " " + string.Join(" ", errors.EnumerateArray().Select(e => Text(e, "message")).Where(m => m is not null));
                }
            }
        }
        catch (JsonException) { }

        if (message.Length > 200) { message = message[..200] + "..."; }

        var hint = status switch
        {
            401 => " (the company id, public key, private key or clientId is wrong, or the keys were regenerated)",
            403 => " (the API member is not allowed to do this; it needs service ticket add and edit on the board, and company inquire)",
            429 => " (rate limited; what was not filed waits for the next run)",
            _ => "",
        };
        return (message.Length == 0 ? "no detail" : message) + hint;
    }

    private static ConnectWiseTicket Ticket(JsonElement element) => new(
        element.GetProperty("id").GetInt32(),
        Text(element, "summary") ?? "",
        element.TryGetProperty("closedFlag", out var closed) && closed.ValueKind == JsonValueKind.True,
        element.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.Object ? Text(status, "name") : null);

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>
    /// A string value in a ConnectWise conditions expression: double-quoted,
    /// with nothing inside that could end the quote or mean something else.
    /// </summary>
    private static string Quote(string value)
    {
        var clean = new string([.. (value ?? "").Where(c => c != '"' && c != '\\' && !char.IsControl(c))]).Trim();
        return $"\"{clean}\"";
    }
}

/// <summary>
/// How an event becomes a ticket: its title, its marker, the text a tech
/// reads, and which finding it belongs to.
/// </summary>
internal static class ConnectWiseTickets
{
    /// <summary>
    /// Eight hex characters of the event's id in the ticket summary, so a
    /// create whose answer was lost can be found by searching for it.
    /// </summary>
    public static string Marker(string eventId) =>
        "[dm:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(eventId)))[..8].ToLowerInvariant() + "]";

    /// <summary>
    /// The finding an event belongs to, so a repeat is a note on the ticket
    /// that is already open rather than a second ticket.
    /// </summary>
    public static string RemoteKey(WebhookEvent evt, string domainId) =>
        $"{evt.Type}:{domainId}:{evt.DnsDrift?.RecordType ?? ""}";

    /// <summary>
    /// "DMARC: client: what changed [dm:marker]", cut to ConnectWise's limit
    /// with the marker always kept.
    /// </summary>
    public static string Summary(WebhookEvent evt, string marker)
    {
        var suffix = " " + marker;
        var text = $"DMARC: {evt.Client?.Name ?? evt.Domain ?? "?"}: {OneLine(evt.Summary)}";
        var room = ConnectWiseClient.SummaryLimit - suffix.Length;
        if (text.Length > room) { text = text[..(room - 1)].TrimEnd() + "…"; }
        return text + suffix;
    }

    /// <summary>
    /// The changes that open a ticket when the finding has none open: first
    /// seen, back after its source resolved it, or worse. Not the source
    /// seeing it again after a failed observation, which changes nothing for
    /// whoever closed the ticket.
    /// </summary>
    public static bool OpensTicket(FindingEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        return evt.Kind switch
        {
            FindingEventKinds.Observed => evt.FromValue is null,
            FindingEventKinds.Reopened or FindingEventKinds.SeverityChanged or FindingEventKinds.TypeChanged => true,
            _ => false,
        };
    }

    /// <summary>
    /// The changes worth a note while a tech has the ticket: what changed,
    /// what its source or a person decided. Not a failed observation, and
    /// not the source seeing it again after one.
    /// </summary>
    public static bool IsNoteworthy(FindingEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        return evt.Kind is not (FindingEventKinds.Observed or FindingEventKinds.SourceUnknown);
    }

    /// <summary>"DMARC: client: the finding [dm:marker]", for a ticket from a finding.</summary>
    public static string Summary(FindingContract finding, string marker)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var who = finding.Client.Name.Length > 0 ? finding.Client.Name : finding.Domain ?? "?";
        var suffix = " " + marker;
        var text = $"DMARC: {who}: {OneLine(finding.Title)}";
        var room = ConnectWiseClient.SummaryLimit - suffix.Length;
        if (text.Length > room) { text = text[..(room - 1)].TrimEnd() + "…"; }
        return text + suffix;
    }

    /// <summary>What a tech reads on a ticket from a finding: the finding, the record if it is one, and where the evidence is.</summary>
    /// <param name="drift">The record before and after, for a DNS finding; null for any other.</param>
    /// <param name="previousTicket">A closed ticket this finding had before, named so the history is one click away.</param>
    public static string Description(FindingContract finding, WebhookDnsDrift? drift, int? previousTicket = null)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var lines = new List<string>();

        if (previousTicket is { } previous)
        {
            lines.Add($"Previously ticket #{previous.ToString(CultureInfo.InvariantCulture)}, since closed.");
            lines.Add("");
        }

        lines.Add($"{(finding.Client.Name.Length > 0 ? finding.Client.Name : "Unknown client")}{(finding.Client.Slug.Length > 0 ? $" ({finding.Client.Slug})" : "")}: {finding.Domain ?? "-"}");
        lines.Add($"Severity: {finding.Severity}");
        lines.Add(OneLine(finding.Title));
        AddRecord(lines, drift);

        lines.Add("");
        lines.Add($"First seen: {When(finding.ObservedAt)}; seen {finding.ObservationCount.ToString(CultureInfo.InvariantCulture)} time(s), last {When(finding.LastObservedAt)}");
        if (finding.EvidenceLink is not null) { lines.Add($"Dashboard: {finding.EvidenceLink}"); }
        lines.Add($"Source: DMARC Monitor, finding {finding.FindingId}");

        return string.Join("\n", lines);
    }

    /// <summary>A note on the finding's open ticket: what just changed, in a tech's words.</summary>
    public static string Note(FindingContract finding, FindingEvent evt, WebhookDnsDrift? drift)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(evt);

        var by = evt.Actor.Length > 0 ? evt.Actor : "somebody";
        var headline = evt.Kind switch
        {
            FindingEventKinds.Reopened => "Seen again after its source had resolved it",
            FindingEventKinds.SeverityChanged => $"Severity {evt.FromValue ?? "?"} → {evt.ToValue ?? "?"}: {OneLine(finding.Title)}",
            FindingEventKinds.TypeChanged => $"Now {evt.ToValue ?? "?"}: {OneLine(finding.Title)}",
            FindingEventKinds.SourceResolved => "Resolved by its source",
            FindingEventKinds.Acknowledged => $"Acknowledged in DMARC Monitor by {by}",
            FindingEventKinds.AnalystStateChanged => $"Marked {evt.ToValue ?? "?"} in DMARC Monitor by {by}",
            FindingEventKinds.ExceptionApplied => $"An exception was recorded in DMARC Monitor by {by}",
            FindingEventKinds.ExceptionExpired => "The exception on this finding has expired; it is back in the queue",
            FindingEventKinds.ExceptionEnded => $"The exception on this finding was ended by {by}",
            FindingEventKinds.RemediationStaged => $"Remediation: {evt.ToValue ?? "off the chain"}",
            _ => evt.Kind,
        };

        var lines = new List<string> { $"{headline} at {When(evt.At)}." };
        if (evt.Note is { Length: > 0 } note && evt.Kind is not (FindingEventKinds.SeverityChanged or FindingEventKinds.TypeChanged))
        {
            lines.Add(OneLine(note));
        }
        if (evt.Kind == FindingEventKinds.SourceResolved) { lines.Add("Close this ticket if nothing else is needed."); }
        if (evt.Kind is FindingEventKinds.Reopened or FindingEventKinds.SeverityChanged or FindingEventKinds.TypeChanged) { AddRecord(lines, drift); }

        lines.Add("");
        lines.Add($"Source: DMARC Monitor, finding {finding.FindingId}, event {evt.Id}");
        return string.Join("\n", lines);
    }

    private static void AddRecord(List<string> lines, WebhookDnsDrift? drift)
    {
        if (drift is null) { return; }
        lines.Add("");
        lines.Add($"Record: {drift.RecordType.ToUpperInvariant()}");
        lines.Add($"Was: {drift.OldValue ?? "(not published)"}");
        lines.Add($"Now: {drift.NewValue ?? "(not published)"}");
    }

    /// <summary>What a tech reads: everything the alert knows, and where the evidence is.</summary>
    /// <param name="previousTicket">A closed ticket this finding had before, named so the history is one click away.</param>
    public static string Description(WebhookEvent evt, int? previousTicket = null, bool again = false)
    {
        var lines = new List<string>();

        if (again)
        {
            lines.Add($"Seen again at {When(evt.OccurredAt)}.");
            lines.Add("");
        }
        else if (previousTicket is { } previous)
        {
            lines.Add($"Previously ticket #{previous.ToString(CultureInfo.InvariantCulture)}, since closed.");
            lines.Add("");
        }

        lines.Add($"{evt.Client?.Name ?? "Unknown client"}{(evt.Client is null ? "" : $" ({evt.Client.Slug})")}: {evt.Domain ?? "-"}");
        lines.Add($"Severity: {evt.Severity ?? "info"}");
        lines.Add(OneLine(evt.Summary));

        if (evt.DnsDrift is { } drift)
        {
            lines.Add("");
            lines.Add($"Record: {drift.RecordType.ToUpperInvariant()}");
            lines.Add($"Was: {drift.OldValue ?? "(not published)"}");
            lines.Add($"Now: {drift.NewValue ?? "(not published)"}");
        }

        if (evt.WasExpected == true)
        {
            lines.Add("");
            lines.Add("This change was applied from the DMARC Monitor dashboard shortly before, so it is expected unless nobody here did that.");
        }

        lines.Add("");
        lines.Add($"Seen: {When(evt.OccurredAt)}");
        if (evt.Link is not null) { lines.Add($"Dashboard: {evt.Link}"); }
        lines.Add($"Source: DMARC Monitor, event {evt.Id}");

        return string.Join("\n", lines);
    }

    private static string When(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);

    private static string OneLine(string? text) =>
        string.Join(" ", (text ?? "").Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
}
