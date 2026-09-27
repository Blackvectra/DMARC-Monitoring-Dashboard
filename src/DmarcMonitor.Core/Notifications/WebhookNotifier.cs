using System.Globalization;
using System.Text;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Updates;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Notifications;

/// <summary>What one run did for one organization's webhook.</summary>
/// <param name="Waiting">Events still to go: not reached this run, or after a failure stopped it.</param>
/// <param name="Error">Why the run stopped early, or why it could not start.</param>
public sealed record DeliveryRun(string TenantSlug, string Destination, int Delivered, int Failed, int Waiting, string? Error)
{
    public bool Worked => Failed == 0 && Error is null;
}

/// <summary>
/// Sends each organization's new DNS drift to its webhook, and remembers what
/// went.
/// </summary>
/// <remarks>
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
/// answer was lost on the way back is harmless to repeat.
/// </para>
/// <para>
/// Events detected before the webhook was set up are never sent, and one that
/// has not gone after <see cref="GiveUpAfter"/> stops being tried: by then it
/// is history, still on the DNS changes page, rather than news.
/// </para>
/// </remarks>
public sealed class WebhookNotifier(string databasePath, ISecretStore secrets, HttpMessageHandler? handler = null, TimeProvider? clock = null)
{
    public const int BatchSize = 500;
    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromDays(14);
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly WebhookStore _store = new(databasePath, secrets, clock);

    /// <summary>Delivers what is waiting, for one organization or for every one that has a webhook.</summary>
    public async Task<IReadOnlyList<DeliveryRun>> SendAsync(string? tenantSlug = null, CancellationToken ct = default)
    {
        IReadOnlyList<Webhook> hooks = tenantSlug is null
            ? await _store.ListAsync(ct).ConfigureAwait(false)
            : await _store.GetAsync(tenantSlug, ct).ConfigureAwait(false) is { } one ? [one] : [];

        using var http = CreateClient();
        var runs = new List<DeliveryRun>();
        foreach (var hook in hooks)
        {
            runs.Add(await SendAsync(hook, http, ct).ConfigureAwait(false));
        }
        return runs;
    }

    /// <summary>
    /// Sends one signed "ping" event and says what came back, so a receiver
    /// can be proved working before there is a real change to send.
    /// </summary>
    public async Task<DeliveryRun> PingAsync(string tenantSlug, CancellationToken ct = default)
    {
        var hook = await _store.GetAsync(tenantSlug, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"'{tenantSlug}' has no webhook. Set one with: dmarc notify set --org {tenantSlug} --url <https address>");

        var credential = await _store.CredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null) { return await MissingKeyAsync(hook, ct).ConfigureAwait(false); }

        var ping = new WebhookEvent
        {
            Id = Guid.NewGuid().ToString(),
            Type = WebhookEvent.PingType,
            OccurredAt = _clock.GetUtcNow(),
            Organization = new WebhookOrganization(hook.TenantId, hook.TenantSlug),
            Summary = "A test event from dmarc notify test. Nothing changed.",
        };

        using var http = CreateClient();
        var (_, error) = await PostAsync(http, credential, ping, ct).ConfigureAwait(false);
        await RecordOutcomeAsync(hook, error, ct).ConfigureAwait(false);
        return new DeliveryRun(hook.TenantSlug, hook.Destination, error is null ? 1 : 0, error is null ? 0 : 1, 0, error);
    }

    private async Task<DeliveryRun> SendAsync(Webhook hook, HttpClient http, CancellationToken ct)
    {
        var credential = await _store.CredentialAsync(hook, ct).ConfigureAwait(false);
        if (credential is null) { return await MissingKeyAsync(hook, ct).ConfigureAwait(false); }

        var pending = await PendingAsync(hook, ct).ConfigureAwait(false);
        int delivered = 0, failed = 0;
        string? error = null;

        foreach (var item in pending)
        {
            var (status, problem) = await PostAsync(http, credential, item.Event, ct).ConfigureAwait(false);
            await RecordAttemptAsync(hook, item, status, problem, ct).ConfigureAwait(false);

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

    private sealed record PendingEvent(string ClientId, WebhookEvent Event);

    /// <summary>
    /// The organization's drift nobody has delivered yet, across every client's
    /// file, oldest first.
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
                   e.old_value, e.new_value, e.summary, e.severity, e.was_expected
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
            result.Add(new PendingEvent(reader.GetString(1), new WebhookEvent
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
        HttpClient http, WebhookCredential credential, WebhookEvent evt, CancellationToken ct)
    {
        var body = evt.ToJson();
        var timestamp = _clock.GetUtcNow().ToUnixTimeSeconds();

        using var request = new HttpRequestMessage(HttpMethod.Post, credential.Url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Add(WebhookSigner.TimestampHeader, timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(WebhookSigner.SignatureHeader, WebhookSigner.Sign(credential.Secret, timestamp, body));
        request.Headers.Add(WebhookSigner.EventIdHeader, evt.Id);

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

    private async Task RecordAttemptAsync(Webhook hook, PendingEvent item, int? status, string? error, CancellationToken ct)
    {
        await using var db = await OpenRegistryAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO webhook_deliveries
                (webhook_id, event_id, client_id, attempts, delivered_at, last_attempt_at, last_status, last_error)
            VALUES ($webhook, $event, $client, 1, $delivered, $now, $status, $error)
            ON CONFLICT (webhook_id, event_id) DO UPDATE SET
                attempts = attempts + 1,
                delivered_at = excluded.delivered_at,
                last_attempt_at = excluded.last_attempt_at,
                last_status = excluded.last_status,
                last_error = excluded.last_error
            """;
        var now = WebhookStore.Stamp(_clock.GetUtcNow());
        command.Parameters.AddWithValue("$webhook", hook.Id);
        command.Parameters.AddWithValue("$event", item.Event.Id);
        command.Parameters.AddWithValue("$client", item.ClientId);
        command.Parameters.AddWithValue("$delivered", error is null ? now : DBNull.Value);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
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
        var error = $"the address and signing key are not in the secret store this run was given. {secrets.Description} "
                    + "Set the webhook again, or pass the secrets folder it was set with.";
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
