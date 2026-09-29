using System.Globalization;
using System.Text;
using System.Text.Json;
using DmarcMonitor.Core.Findings;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Updates;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Notifications;

/// <summary>What one run did for one organization's destination.</summary>
/// <param name="Waiting">Events still to go: not reached this run, or after a failure stopped it.</param>
/// <param name="Error">Why the run stopped early, or why it could not start.</param>
public sealed record DeliveryRun(string TenantSlug, string Destination, int Delivered, int Failed, int Waiting, string? Error)
{
    /// <summary>
    /// Clients whose events could not be filed because no ConnectWise company
    /// is set for them. Their events wait, and are not a failure of the
    /// destination: the fix is a mapping, not a receiver.
    /// </summary>
    public IReadOnlyList<string> Unmapped { get; init; } = [];

    public bool Worked => Failed == 0 && Error is null;
}

/// <summary>What proving a ConnectWise destination found.</summary>
public sealed record ConnectWiseCheck(bool Worked, string Message);

/// <summary>
/// Sends each organization's findings to its destinations, and remembers
/// what went.
/// </summary>
/// <remarks>
/// <para>
/// A destination on the finding contract is told about each change on a
/// finding - first seen, worse, resolved by its source, back again, what a
/// person decided - once, as dmarc-monitor.finding.v1; one on the older
/// event contract is told about each DNS change, as before. A ConnectWise
/// destination gets one ticket per finding, keyed by the finding's id, and
/// a note on that ticket for what changes while a tech has it open.
/// </para>
/// <para>
/// Oldest first, and a run stops at the first failure. An endpoint that is
/// down fails every request the same way, so trying the other 499 only says
/// it 499 more times; and stopping keeps the order, so a receiver never sees
/// a domain's second change before its first. What was not sent waits for the
/// next run, which after a nightly scan is the next night - or any time
/// somebody runs <c>dmarc notify send</c>.
/// </para>
/// <para>
/// Every event carries the same id on every attempt, and a receiver is
/// expected to ignore one it has seen, so a delivery that worked but whose
/// answer was lost on the way back is harmless to repeat. A ConnectWise
/// ticket carries a marker of the id in its summary for the same reason.
/// </para>
/// <para>
/// Events detected before the destination was set up are never sent, and one
/// that has not gone after <see cref="GiveUpAfter"/> stops being tried: by
/// then it is history, still on the DNS changes page, rather than news.
/// </para>
/// </remarks>
public sealed class WebhookNotifier(string databasePath, ISecretStore secrets, HttpMessageHandler? handler = null, TimeProvider? clock = null)
{
    public const int BatchSize = 500;
    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromDays(14);
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly WebhookStore _store = new(databasePath, secrets, clock);
    private readonly ClientSettingsStore _settings = new(databasePath);
    private readonly FindingStore _findings = new(databasePath);
    private readonly ClientDatabases _files = new(databasePath);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Delivers what is waiting, for one organization or for every one that has a destination.</summary>
    public async Task<IReadOnlyList<DeliveryRun>> SendAsync(string? tenantSlug = null, CancellationToken ct = default)
    {
        var hooks = tenantSlug is null
            ? await _store.ListAsync(ct).ConfigureAwait(false)
            : await _store.ForOrganizationAsync(tenantSlug, ct).ConfigureAwait(false);

        using var http = CreateClient();
        var runs = new List<DeliveryRun>();
        foreach (var hook in hooks)
        {
            runs.Add(hook.IsConnectWise
                ? await SendToConnectWiseAsync(hook, http, ct).ConfigureAwait(false)
                : await SendAsync(hook, http, ct).ConfigureAwait(false));
        }
        return runs;
    }

    /// <summary>
    /// Sends one signed "ping" event and says what came back, so a receiver
    /// can be proved working before there is a real change to send.
    /// </summary>
    public async Task<DeliveryRun> PingAsync(string tenantSlug, CancellationToken ct = default)
    {
        var hook = await _store.GetAsync(tenantSlug, WebhookStore.WebhookKind, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"'{tenantSlug}' has no webhook. Set one with: dmarc notify set --org {tenantSlug} --url <https address>");

        var credential = await _store.CredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null) { return await MissingKeyAsync(hook, ct).ConfigureAwait(false); }

        // In the shape the destination has asked for, so what it proves is
        // that it can read what it will be sent.
        string body, id;
        if (hook.SendsFindings)
        {
            var ping = FindingContract.Ping(hook.TenantId, hook.TenantSlug, _clock.GetUtcNow());
            (body, id) = (ping.ToJson(), ping.Id);
        }
        else
        {
            var ping = new WebhookEvent
            {
                Id = Guid.NewGuid().ToString(),
                Type = WebhookEvent.PingType,
                OccurredAt = _clock.GetUtcNow(),
                Organization = new WebhookOrganization(hook.TenantId, hook.TenantSlug),
                Summary = "A test event from dmarc notify test. Nothing changed.",
            };
            (body, id) = (ping.ToJson(), ping.Id);
        }

        using var http = CreateClient();
        var (_, error) = await PostAsync(http, credential, body, id, ct).ConfigureAwait(false);
        await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        return new DeliveryRun(hook.TenantSlug, hook.Destination, error is null ? 1 : 0, error is null ? 0 : 1, 0, error);
    }

    /// <summary>
    /// Proves a ConnectWise destination: the credential signs in, the board
    /// exists, and - when a client is named - a test ticket can be created on
    /// that client's company. Nothing else is written there.
    /// </summary>
    public async Task<ConnectWiseCheck> TestConnectWiseAsync(string tenantSlug, string? clientSlug = null, CancellationToken ct = default)
    {
        var hook = await _store.GetAsync(tenantSlug, WebhookStore.ConnectWiseKind, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"'{tenantSlug}' has no ConnectWise destination. Set one with: dmarc notify set --kind connectwise --org {tenantSlug} ...");

        var credential = await _store.ConnectWiseCredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null)
        {
            var missing = await MissingKeyAsync(hook, ct).ConfigureAwait(false);
            return new ConnectWiseCheck(false, missing.Error!);
        }

        var board = hook.ConnectWise?.Board ?? "";
        using var http = CreateClient();
        var client = new ConnectWiseClient(http, credential);

        try
        {
            await client.CheckAsync(ct).ConfigureAwait(false);

            if (!await client.BoardExistsAsync(board, ct).ConfigureAwait(false))
            {
                var noBoard = $"Signed in to {hook.Destination}, but it has no service board called '{board}'.";
                await RecordOutcomeAsync(hook, noBoard, ct).ConfigureAwait(false);
                return new ConnectWiseCheck(false, noBoard);
            }

            if (clientSlug is null)
            {
                await RecordOutcomeAsync(hook, null, ct).ConfigureAwait(false);
                return new ConnectWiseCheck(true,
                    $"Signed in to {hook.Destination}; board '{board}' found. Add --client <slug> to create a test ticket on that client's company.");
            }

            var found = await ClientAsync(hook.TenantId, clientSlug, ct).ConfigureAwait(false);
            if (found is not { } target)
            {
                return new ConnectWiseCheck(false, $"'{tenantSlug}' has no client '{clientSlug}'.");
            }

            var company = await CompanyAsync(target.Id, ct).ConfigureAwait(false);
            if (company is not { } companyId)
            {
                return new ConnectWiseCheck(false,
                    $"'{clientSlug}' has no ConnectWise company. Set it with: dmarc client set-connectwise --client {clientSlug} --company <id>");
            }

            var marker = ConnectWiseTickets.Marker(Guid.NewGuid().ToString());
            var ticket = await client.CreateTicketAsync(new NewTicket(
                $"DMARC Monitor test ticket - safe to close {marker}", board, companyId,
                hook.ConnectWise?.Status, hook.ConnectWise?.PriorityWarning,
                "A test from dmarc notify test. Nothing changed. Close this ticket."), ct).ConfigureAwait(false);

            await RecordOutcomeAsync(hook, null, ct).ConfigureAwait(false);
            return new ConnectWiseCheck(true, $"Created ticket #{ticket.Id.ToString(CultureInfo.InvariantCulture)} on '{board}' for {target.Name}. Close it there.");
        }
        catch (ConnectWiseException ex)
        {
            await RecordOutcomeAsync(hook, ex.Message, ct).ConfigureAwait(false);
            return new ConnectWiseCheck(false, ex.Message);
        }
    }

    /// <summary>
    /// Companies in the organization's ConnectWise whose name or identifier
    /// contains the text, for a person to pick a client's from.
    /// </summary>
    public async Task<IReadOnlyList<ConnectWiseCompany>> SearchCompaniesAsync(string tenantSlug, string text, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);

        var hook = await _store.GetAsync(tenantSlug, WebhookStore.ConnectWiseKind, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"'{tenantSlug}' has no ConnectWise destination. Set one with: dmarc notify set --kind connectwise --org {tenantSlug} ...");

        var credential = await _store.ConnectWiseCredentialAsync(hook, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException((await MissingKeyAsync(hook, ct).ConfigureAwait(false)).Error!);

        using var http = CreateClient();
        return await new ConnectWiseClient(http, credential).SearchCompaniesAsync(text, ct).ConfigureAwait(false);
    }

    private async Task<DeliveryRun> SendAsync(Webhook hook, HttpClient http, CancellationToken ct)
    {
        var credential = await _store.CredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null) { return await MissingKeyAsync(hook, ct).ConfigureAwait(false); }

        // What goes, and the id each message carries: a finding event, or a
        // DNS change for a destination on the older contract.
        List<(string EventId, string ClientId, string Body)> pending;
        if (hook.SendsFindings)
        {
            pending = (await UndeliveredAsync(hook, ct).ConfigureAwait(false))
                .Select(c => (c.Event.Id, c.Finding.ClientId, FindingContract.For(c.Finding, c.Event, hook.TenantSlug, hook.LinkBase).ToJson()))
                .ToList();
        }
        else
        {
            pending = (await PendingAsync(hook, ct).ConfigureAwait(false))
                .Select(e => (e.Event.Id, e.ClientId, e.Event.ToJson()))
                .ToList();
        }

        int delivered = 0, failed = 0;
        string? error = null;

        foreach (var (eventId, clientId, body) in pending)
        {
            var (status, problem) = await PostAsync(http, credential, body, eventId, ct).ConfigureAwait(false);
            await RecordAttemptAsync(hook, eventId, clientId, status, problem, null, null, ct).ConfigureAwait(false);

            if (problem is not null)
            {
                failed++;
                error = problem;
                break;
            }
            delivered++;
        }

        if (delivered > 0 || error is not null)
        {
            await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        }

        var waiting = pending.Count - delivered;
        return new DeliveryRun(hook.TenantSlug, hook.Destination, delivered, failed, waiting, error);
    }

    /// <summary>
    /// Files each pending event in ConnectWise: a ticket per finding, a note
    /// on the open ticket when the finding repeats.
    /// </summary>
    /// <remarks>
    /// A client with no company set is skipped rather than failing the run,
    /// because the fix is a mapping the operator has to make, and one unmapped
    /// client must not hold every other client's tickets. Its events wait, and
    /// the run names it.
    /// </remarks>
    private async Task<DeliveryRun> SendToConnectWiseAsync(Webhook hook, HttpClient http, CancellationToken ct)
    {
        var credential = await _store.ConnectWiseCredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null) { return await MissingKeyAsync(hook, ct).ConfigureAwait(false); }

        var settings = hook.ConnectWise;
        if (settings is null || string.IsNullOrWhiteSpace(settings.Board))
        {
            var noBoard = "no service board is set for ConnectWise tickets; set the destination again with --board.";
            await RecordOutcomeAsync(hook, noBoard, ct).ConfigureAwait(false);
            return new DeliveryRun(hook.TenantSlug, hook.Destination, 0, 0, 0, noBoard);
        }

        var client = new ConnectWiseClient(http, credential);
        var companies = await _settings.ForOrganizationAsync(hook.TenantId, ClientSettingsStore.ConnectWiseCompany, ct).ConfigureAwait(false);

        return hook.SendsFindings
            ? await FileFindingsAsync(hook, client, settings, companies, ct).ConfigureAwait(false)
            : await FileEventsAsync(hook, client, settings, companies, ct).ConfigureAwait(false);
    }

    /// <summary>Each undelivered change on a finding, into the finding's ticket.</summary>
    private async Task<DeliveryRun> FileFindingsAsync(
        Webhook hook, ConnectWiseClient client, ConnectWiseSettings settings, IReadOnlyDictionary<string, string> companies, CancellationToken ct)
    {
        var pending = await UndeliveredAsync(hook, ct).ConfigureAwait(false);

        var unmapped = new SortedSet<string>(StringComparer.Ordinal);
        int delivered = 0, failed = 0;
        string? error = null;

        foreach (var change in pending)
        {
            var finding = change.Finding;
            if (!companies.TryGetValue(finding.ClientId, out var mapped)
                || !int.TryParse(mapped, NumberStyles.None, CultureInfo.InvariantCulture, out var companyId))
            {
                unmapped.Add(finding.ClientSlug.Length > 0 ? finding.ClientSlug : finding.ClientId);
                continue;
            }

            try
            {
                var ticketId = await FileFindingAsync(hook, client, settings, change, companyId, ct).ConfigureAwait(false);
                await RecordAttemptAsync(hook, change.Event.Id, finding.ClientId, 200, null, finding.Id,
                    ticketId?.ToString(CultureInfo.InvariantCulture), ct).ConfigureAwait(false);
                delivered++;
            }
            catch (ConnectWiseException ex)
            {
                await RecordAttemptAsync(hook, change.Event.Id, finding.ClientId, ex.Status, ex.Message, finding.Id, null, ct).ConfigureAwait(false);
                failed++;
                error = ex.Message;
                break;
            }
        }

        if (delivered > 0 || error is not null)
        {
            await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        }

        return new DeliveryRun(hook.TenantSlug, hook.Destination, delivered, failed, pending.Count - delivered, error)
        {
            Unmapped = [.. unmapped],
        };
    }

    /// <summary>
    /// One change on a finding into ConnectWise: a note on the finding's
    /// ticket while a tech has it open; a new ticket, naming the old one if
    /// there was one, when the finding is new, back or worse; nothing filed
    /// for what a closed ticket does not need to hear. Returns the ticket
    /// the finding is on, if any.
    /// </summary>
    private async Task<int?> FileFindingAsync(
        Webhook hook, ConnectWiseClient client, ConnectWiseSettings settings, FindingChange change, int companyId, CancellationToken ct)
    {
        var (evt, finding) = change;
        var contract = FindingContract.For(finding, evt, hook.TenantSlug, hook.LinkBase);
        var drift = await DriftAsync(finding.ClientId, finding.EvidenceRef, ct).ConfigureAwait(false);

        var previous = await LatestTicketAsync(hook, finding.Id, ct).ConfigureAwait(false);
        if (previous is { } open)
        {
            var ticket = await client.GetTicketAsync(open, ct).ConfigureAwait(false);
            if (ticket is { Closed: false })
            {
                if (ConnectWiseTickets.IsNoteworthy(evt))
                {
                    await client.AddNoteAsync(open, ConnectWiseTickets.Note(contract, evt, drift), ct).ConfigureAwait(false);
                    await NoteTicketAsync(finding, FindingEventKinds.TicketUpdated, open, settings.Board, hook.Destination, ct).ConfigureAwait(false);
                }
                return open;
            }
        }

        if (!ConnectWiseTickets.OpensTicket(evt)) { return previous; }

        // A create whose answer was lost on the way back is already there,
        // carrying this event's marker: found rather than filed twice.
        var marker = ConnectWiseTickets.Marker(evt.Id);
        var existing = await client.FindTicketAsync(marker, ct).ConfigureAwait(false);
        if (existing is not null)
        {
            await NoteTicketAsync(finding, FindingEventKinds.TicketCreated, existing.Id, settings.Board, hook.Destination, ct).ConfigureAwait(false);
            return existing.Id;
        }

        var created = await client.CreateTicketAsync(new NewTicket(
            ConnectWiseTickets.Summary(contract, marker),
            settings.Board,
            companyId,
            settings.Status,
            settings.PriorityFor(contract.Severity),
            ConnectWiseTickets.Description(contract, drift, previousTicket: previous)), ct).ConfigureAwait(false);
        await NoteTicketAsync(finding, FindingEventKinds.TicketCreated, created.Id, settings.Board, hook.Destination, ct).ConfigureAwait(false);
        return created.Id;
    }

    /// <summary>The ticket, on the finding's own history, so a page can show its number.</summary>
    private Task<FindingEvent> NoteTicketAsync(Finding finding, string kind, int ticketId, string board, string destination, CancellationToken ct) =>
        _findings.AppendEventAsync(finding, kind, "connectwise", _clock.GetUtcNow(),
            toValue: ticketId.ToString(CultureInfo.InvariantCulture),
            note: $"Ticket #{ticketId.ToString(CultureInfo.InvariantCulture)} on '{board}' at {destination}.",
            payloadJson: JsonSerializer.Serialize(new { ticket = ticketId, board, destination }, Json), ct: ct);

    /// <summary>The record before and after, for a ticket, from the drift event the finding points at in the client's file.</summary>
    private async Task<WebhookDnsDrift?> DriftAsync(string clientId, string? evidenceRef, CancellationToken ct)
    {
        const string prefix = "drift:";
        if (evidenceRef is null || !evidenceRef.StartsWith(prefix, StringComparison.Ordinal)) { return null; }

        await using var db = await _files.OpenAsync(ClientScope.Client(clientId), ["dns_drift_events"], ct: ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT record_type, old_value, new_value FROM dns_drift_events WHERE id = $id";
        command.Parameters.AddWithValue("$id", evidenceRef[prefix.Length..]);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }
        return new WebhookDnsDrift(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2));
    }

    /// <summary>Each pending DNS change, for a ConnectWise destination on the older contract.</summary>
    private async Task<DeliveryRun> FileEventsAsync(
        Webhook hook, ConnectWiseClient client, ConnectWiseSettings settings, IReadOnlyDictionary<string, string> companies, CancellationToken ct)
    {
        var pending = await PendingAsync(hook, ct).ConfigureAwait(false);

        var unmapped = new SortedSet<string>(StringComparer.Ordinal);
        int delivered = 0, failed = 0;
        string? error = null;

        foreach (var item in pending)
        {
            if (!companies.TryGetValue(item.ClientId, out var mapped)
                || !int.TryParse(mapped, NumberStyles.None, CultureInfo.InvariantCulture, out var companyId))
            {
                unmapped.Add(item.Event.Client?.Slug ?? item.ClientId);
                continue;
            }

            var remoteKey = ConnectWiseTickets.RemoteKey(item.Event, item.DomainId);
            try
            {
                var ticketId = await FileAsync(hook, client, settings, item, companyId, remoteKey, ct).ConfigureAwait(false);
                await RecordAttemptAsync(hook, item.Event.Id, item.ClientId, 200, null, remoteKey, ticketId.ToString(CultureInfo.InvariantCulture), ct).ConfigureAwait(false);
                delivered++;
            }
            catch (ConnectWiseException ex)
            {
                await RecordAttemptAsync(hook, item.Event.Id, item.ClientId, ex.Status, ex.Message, remoteKey, null, ct).ConfigureAwait(false);
                failed++;
                error = ex.Message;
                break;
            }
        }

        if (delivered > 0 || error is not null)
        {
            await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        }

        return new DeliveryRun(hook.TenantSlug, hook.Destination, delivered, failed, pending.Count - delivered, error)
        {
            Unmapped = [.. unmapped],
        };
    }

    /// <summary>One event into ConnectWise; returns the ticket it ended up on.</summary>
    private async Task<int> FileAsync(
        Webhook hook, ConnectWiseClient client, ConnectWiseSettings settings, PendingEvent item, int companyId,
        string remoteKey, CancellationToken ct)
    {
        // The finding's ticket, if this destination has filed one: a note
        // while a tech still has it open, a new ticket naming the old once
        // it is closed.
        var previous = await LatestTicketAsync(hook, remoteKey, ct).ConfigureAwait(false);
        if (previous is { } open)
        {
            var ticket = await client.GetTicketAsync(open, ct).ConfigureAwait(false);
            if (ticket is { Closed: false })
            {
                await client.AddNoteAsync(open, ConnectWiseTickets.Description(item.Event, again: true), ct).ConfigureAwait(false);
                return open;
            }
        }

        // A create whose answer was lost on the way back is already there,
        // carrying this event's marker: found rather than filed twice.
        var marker = ConnectWiseTickets.Marker(item.Event.Id);
        var existing = await client.FindTicketAsync(marker, ct).ConfigureAwait(false);
        if (existing is not null) { return existing.Id; }

        var created = await client.CreateTicketAsync(new NewTicket(
            ConnectWiseTickets.Summary(item.Event, marker),
            settings.Board,
            companyId,
            settings.Status,
            settings.PriorityFor(item.Event.Severity),
            ConnectWiseTickets.Description(item.Event, previousTicket: previous)), ct).ConfigureAwait(false);
        return created.Id;
    }

    private sealed record PendingEvent(string ClientId, string DomainId, WebhookEvent Event);

    /// <summary>
    /// The changes on the organization's findings nobody has delivered here
    /// yet, oldest first: the kinds a destination hears about, on findings at
    /// or above the destination's severity, since it was set up or the last
    /// two weeks, whichever is later.
    /// </summary>
    private Task<IReadOnlyList<FindingChange>> UndeliveredAsync(Webhook hook, CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        var since = hook.CreatedAt > now - GiveUpAfter ? hook.CreatedAt : now - GiveUpAfter;
        return _findings.UndeliveredAsync(hook.Id, hook.TenantId, since, FindingEventKinds.Delivering, Rank(hook.MinSeverity), BatchSize, ct);
    }

    /// <summary>
    /// The organization's drift nobody has delivered here yet, across every
    /// client's file, oldest first: the older contract's feed.
    /// </summary>
    /// <remarks>
    /// The events are in the client files and the record of what was sent is
    /// in the organization's database, so this reads both through one
    /// connection: the organization's as main, the clients' tables made
    /// visible beside it (see ClientDatabases). Which events went where never
    /// leaves the organization's file.
    /// </remarks>
    private async Task<IReadOnlyList<PendingEvent>> PendingAsync(Webhook hook, CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        var since = hook.CreatedAt > now - GiveUpAfter ? hook.CreatedAt : now - GiveUpAfter;

        await using var db = await new ClientDatabases(databasePath)
            .OpenAsync(ClientScope.Organization(hook.TenantId), ["dns_drift_events"], ct: ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT e.id, e.client_id, c.slug, c.name, d.name, e.detected_at, e.record_type,
                   e.old_value, e.new_value, e.summary, e.severity, e.was_expected, e.domain_id
            FROM dns_drift_events e
            JOIN domains d ON d.id = e.domain_id
            JOIN clients c ON c.id = e.client_id
            LEFT JOIN main.webhook_deliveries w ON w.webhook_id = $webhook AND w.event_id = e.id
            WHERE e.tenant_id = $tenant
              AND e.detected_at >= $since
              AND CASE e.severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END >= $min
              AND w.delivered_at IS NULL
            ORDER BY e.detected_at, e.id
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$webhook", hook.Id);
        command.Parameters.AddWithValue("$tenant", hook.TenantId);
        command.Parameters.AddWithValue("$since", WebhookStore.Stamp(since));
        command.Parameters.AddWithValue("$min", Rank(hook.MinSeverity));
        command.Parameters.AddWithValue("$limit", BatchSize);

        var result = new List<PendingEvent>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);

            var domain = reader.GetString(4);
            result.Add(new PendingEvent(reader.GetString(1), reader.GetString(12), new WebhookEvent
            {
                Id = reader.GetString(0),
                Type = WebhookEvent.DnsDriftType,
                OccurredAt = WebhookStore.ParseStamp(reader.GetString(5)) ?? now,
                Organization = new WebhookOrganization(hook.TenantId, hook.TenantSlug),
                Client = new WebhookClient(reader.GetString(1), reader.GetString(2), reader.GetString(3)),
                Domain = domain,
                Severity = reader.GetString(10),
                Summary = reader.GetString(9),
                WasExpected = reader.GetInt64(11) == 1,
                DnsDrift = new WebhookDnsDrift(reader.GetString(6), Text(7), Text(8)),
                Link = hook.LinkBase is null ? null : $"{hook.LinkBase}/domains/{Uri.EscapeDataString(domain)}",
            }));
        }
        return result;
    }

    private async Task<(int? Status, string? Error)> PostAsync(
        HttpClient http, WebhookCredential credential, string body, string eventId, CancellationToken ct)
    {
        var timestamp = _clock.GetUtcNow().ToUnixTimeSeconds();

        using var request = new HttpRequestMessage(HttpMethod.Post, credential.Url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Add(WebhookSigner.TimestampHeader, timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(WebhookSigner.SignatureHeader, WebhookSigner.Sign(credential.Secret, timestamp, body));
        request.Headers.Add(WebhookSigner.EventIdHeader, eventId);

        try
        {
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode) { return (status, null); }

            // What the receiver said is usually the whole diagnosis ("signature
            // does not match", "unknown domain"), so a short piece of it is kept.
            var said = (await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();
            if (said.Length > 200) { said = said[..200] + "..."; }
            return (status, said.Length == 0 ? $"{status} {response.ReasonPhrase}" : $"{status} {response.ReasonPhrase}: {said}");
        }
        catch (HttpRequestException ex)
        {
            return (null, ex.Message);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return (null, $"no answer within {RequestTimeout.TotalSeconds:0} seconds");
        }
    }

    /// <summary>The ticket this destination last filed the finding on, or null.</summary>
    private async Task<int?> LatestTicketAsync(Webhook hook, string remoteKey, CancellationToken ct)
    {
        await using var db = await OpenRegistryAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT remote_id FROM webhook_deliveries
            WHERE webhook_id = $webhook AND remote_key = $key AND remote_id IS NOT NULL AND delivered_at IS NOT NULL
            ORDER BY delivered_at DESC, rowid DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$webhook", hook.Id);
        command.Parameters.AddWithValue("$key", remoteKey);
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) is string id
               && int.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            ? number
            : null;
    }

    private async Task<(string Id, string Name)?> ClientAsync(string tenantId, string clientSlug, CancellationToken ct)
    {
        await using var db = await OpenRegistryAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id, name FROM clients WHERE tenant_id = $tenant AND slug = $slug AND deleted_at IS NULL";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$slug", clientSlug.Trim().ToLowerInvariant());
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? (reader.GetString(0), reader.GetString(1)) : null;
    }

    private async Task<int?> CompanyAsync(string clientId, CancellationToken ct)
    {
        var mapped = await _settings.GetAsync(clientId, ClientSettingsStore.ConnectWiseCompany, ct).ConfigureAwait(false);
        return mapped is not null && int.TryParse(mapped, NumberStyles.None, CultureInfo.InvariantCulture, out var id) ? id : null;
    }

    private async Task RecordAttemptAsync(
        Webhook hook, string eventId, string clientId, int? status, string? error, string? remoteKey, string? remoteId, CancellationToken ct)
    {
        await using var db = await OpenRegistryAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO webhook_deliveries
                (webhook_id, event_id, client_id, attempts, delivered_at, last_attempt_at, last_status, last_error, remote_key, remote_id)
            VALUES ($webhook, $event, $client, 1, $delivered, $now, $status, $error, $key, $remote)
            ON CONFLICT (webhook_id, event_id) DO UPDATE SET
                attempts = attempts + 1,
                delivered_at = excluded.delivered_at,
                last_attempt_at = excluded.last_attempt_at,
                last_status = excluded.last_status,
                last_error = excluded.last_error,
                remote_key = COALESCE(excluded.remote_key, remote_key),
                remote_id = COALESCE(excluded.remote_id, remote_id)
            """;
        var now = WebhookStore.Stamp(_clock.GetUtcNow());
        command.Parameters.AddWithValue("$webhook", hook.Id);
        command.Parameters.AddWithValue("$event", eventId);
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$delivered", error is null ? now : DBNull.Value);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
        command.Parameters.AddWithValue("$key", (object?)remoteKey ?? DBNull.Value);
        command.Parameters.AddWithValue("$remote", (object?)remoteId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private async Task RecordOutcomeAsync(Webhook hook, string? error, CancellationToken ct)
    {
        await using var db = await OpenRegistryAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = error is null
            ? "UPDATE webhooks SET last_delivered_at = $now WHERE id = $id"
            : "UPDATE webhooks SET last_error = $error, last_error_at = $now WHERE id = $id";
        command.Parameters.AddWithValue("$now", WebhookStore.Stamp(_clock.GetUtcNow()));
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
        command.Parameters.AddWithValue("$id", hook.Id);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The row points at a key the store does not have: a secrets folder that
    /// was not copied with the database, or a run given the wrong one. Said
    /// plainly, because "401 from the receiver" would send somebody looking in
    /// the wrong place.
    /// </summary>
    private async Task<DeliveryRun> MissingKeyAsync(Webhook hook, CancellationToken ct)
    {
        var what = hook.IsConnectWise ? "the ConnectWise keys are" : "the address and signing key are";
        var error = $"{what} not in the secret store this run was given. {secrets.Description} "
                    + "Set the destination again, or pass the secrets folder it was set with.";
        await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        return new DeliveryRun(hook.TenantSlug, hook.Destination, 0, 0, 0, error);
    }

    private async Task<SqliteConnection> OpenRegistryAsync(CancellationToken ct)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            ForeignKeys = true,
            Pooling = false,
        }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);
        return db;
    }

    private HttpClient CreateClient()
    {
        // No redirects: the address somebody configured is where signed
        // client data goes, and a 3xx is a thing to tell them about, not to
        // follow somewhere they did not choose.
        var client = handler is null
            ? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) })
            : new HttpClient(handler, disposeHandler: false);
        client.Timeout = RequestTimeout;
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"DmarcMonitor/{BuildInfo.Version}");
        return client;
    }

    private static int Rank(string severity) => severity switch
    {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    };
}
