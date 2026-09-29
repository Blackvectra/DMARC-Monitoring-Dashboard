using System.Globalization;
using System.Net;
using System.Text.Json;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Notifications;

/// <summary>An organization's destination, as a person may see it: no address past the host, no secret.</summary>
public sealed record Webhook
{
    public required string Id { get; init; }
    public required string TenantId { get; init; }
    public required string TenantSlug { get; init; }

    /// <summary><see cref="WebhookStore.WebhookKind"/> or <see cref="WebhookStore.ConnectWiseKind"/>.</summary>
    public string Kind { get; init; } = WebhookStore.WebhookKind;

    /// <summary>Scheme and host only. The full address is a secret for most chat tools.</summary>
    public required string Destination { get; init; }

    public required string CredentialRef { get; init; }
    public required string MinSeverity { get; init; }
    public string? LinkBase { get; init; }

    /// <summary>
    /// Which contract it receives: <see cref="WebhookStore.FindingVersion"/>,
    /// one message per change on a finding, or <see cref="WebhookStore.EventVersion"/>,
    /// the older one message per DNS change (docs/WEBHOOKS.md).
    /// </summary>
    public string PayloadVersion { get; init; } = WebhookStore.FindingVersion;

    public bool SendsFindings => PayloadVersion == WebhookStore.FindingVersion;

    /// <summary>Where tickets go, for a ConnectWise destination; null for a webhook.</summary>
    public ConnectWiseSettings? ConnectWise { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
    public required string CreatedBy { get; init; }
    public DateTimeOffset? LastDeliveredAt { get; init; }
    public string? LastError { get; init; }
    public DateTimeOffset? LastErrorAt { get; init; }

    public bool IsConnectWise => Kind == WebhookStore.ConnectWiseKind;

    /// <summary>The last attempt failed, and nothing has been delivered since.</summary>
    public bool IsFailing => LastErrorAt is { } failed && (LastDeliveredAt is not { } ok || failed > ok);
}

/// <summary>What is kept in the secret store for a webhook: where it goes, and the key that signs it.</summary>
internal sealed record WebhookCredential(string Url, string Secret);

/// <summary>
/// Where an organization's findings are sent.
/// </summary>
/// <remarks>
/// <para>
/// One destination of each kind per organization: a webhook, given a signed
/// POST per change, and a ConnectWise PSA, given a ticket per finding
/// (docs/CONNECTWISE.md). Setting one again replaces its address or keys but
/// keeps its history, so events that were waiting still go - to the new
/// address.
/// </para>
/// <para>
/// The same rule as DNS provider credentials: the database never holds a
/// secret. The full address and the signing key - or the four parts of a
/// ConnectWise credential - are in the secret store under one credential
/// reference, and the database keeps the pointer and a display form of where
/// it goes.
/// </para>
/// </remarks>
public sealed class WebhookStore(string databasePath, ISecretStore secrets, TimeProvider? clock = null)
{
    public const string WebhookKind = "webhook";
    public const string ConnectWiseKind = "connectwise";
    public static readonly IReadOnlyList<string> Kinds = [WebhookKind, ConnectWiseKind];

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public static readonly IReadOnlyList<string> Severities = ["info", "warning", "critical"];

    /// <summary>The contract a new destination gets: dmarc-monitor.finding.v1.</summary>
    public const string FindingVersion = "finding.v1";

    /// <summary>The older contract, one message per DNS change; kept for a destination that asks for it.</summary>
    public const string EventVersion = "event.v1";

    public static readonly IReadOnlyList<string> PayloadVersions = [FindingVersion, EventVersion];

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
        Pooling = false,
    }.ToString();

    public ISecretStore Secrets { get; } = secrets;

    /// <summary>Every organization's destinations, of every kind.</summary>
    public async Task<IReadOnlyList<Webhook>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = Select + " ORDER BY t.slug, w.kind";
        return await ReadAsync(command, ct).ConfigureAwait(false);
    }

    /// <summary>One organization's destinations, of every kind.</summary>
    public async Task<IReadOnlyList<Webhook>> ForOrganizationAsync(string tenantSlug, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = Select + " WHERE t.slug = $slug ORDER BY w.kind";
        command.Parameters.AddWithValue("$slug", tenantSlug.Trim().ToLowerInvariant());
        return await ReadAsync(command, ct).ConfigureAwait(false);
    }

    /// <summary>One organization's destination of one kind, or null.</summary>
    public async Task<Webhook?> GetAsync(string tenantSlug, string kind = WebhookKind, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = Select + " WHERE t.slug = $slug AND w.kind = $kind";
        command.Parameters.AddWithValue("$slug", tenantSlug.Trim().ToLowerInvariant());
        command.Parameters.AddWithValue("$kind", ParseKind(kind));
        return (await ReadAsync(command, ct).ConfigureAwait(false)).SingleOrDefault();
    }

    /// <summary>Points an organization's findings at an address, replacing whatever webhook it had.</summary>
    /// <exception cref="ArgumentException">The address, secret or severity is not one this accepts.</exception>
    /// <exception cref="InvalidOperationException">No such organization, or no secret store to keep the key in.</exception>
    public async Task<Webhook> SetAsync(
        string tenantSlug, string url, string secret, string minSeverity, string? linkBase, string by,
        string payloadVersion = FindingVersion, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(by);

        var payload = ParsePayloadVersion(payloadVersion);
        var address = ParseAddress(url);
        var link = linkBase is null ? null : ParseLinkBase(linkBase);
        if (secret is null || secret.Trim().Length < WebhookSigner.MinimumSecretLength)
        {
            throw new ArgumentException(
                $"The signing secret must be at least {WebhookSigner.MinimumSecretLength} characters. "
                + "Generate one with: openssl rand -hex 32");
        }

        var severity = ParseSeverity(minSeverity);
        var tenant = await EnsureTenantAsync(tenantSlug, ct).ConfigureAwait(false);
        var existing = await GetAsync(tenant.Slug, WebhookKind, ct).ConfigureAwait(false);

        // The new key is stored before the row points at it and the old one is
        // removed after, so there is no moment where the row names a key that
        // is not there.
        var credentialRef = CredentialRef.New(tenant.Slug, "webhook");
        await Secrets.SetAsync(credentialRef,
            JsonSerializer.Serialize(new WebhookCredential(address.AbsoluteUri, secret.Trim())), ct).ConfigureAwait(false);

        await UpsertAsync(existing, tenant.Id, WebhookKind, Destination(address), credentialRef, severity,
            link?.AbsoluteUri.TrimEnd('/'), null, payload, by, ct).ConfigureAwait(false);

        if (existing is not null && existing.CredentialRef != credentialRef)
        {
            await Secrets.RemoveAsync(existing.CredentialRef, ct).ConfigureAwait(false);
        }

        await new AuditLog(databasePath).RecordAsync(tenant.Id, by,
            existing is null ? "webhook.set" : "webhook.replace",
            $"to {Destination(address)}, {severity} and above, {payload}", ct).ConfigureAwait(false);

        return (await GetAsync(tenant.Slug, WebhookKind, ct).ConfigureAwait(false))!;
    }

    /// <summary>
    /// Points an organization's findings at its ConnectWise PSA, as tickets,
    /// replacing whatever ConnectWise destination it had.
    /// </summary>
    /// <param name="site">The ConnectWise API host, e.g. https://api-na.myconnectwise.net, with or without the version path.</param>
    /// <param name="companyId">The organization's own ConnectWise company id (the login's), not a client's.</param>
    /// <param name="clientId">The integration's clientId from developer.connectwise.com.</param>
    /// <exception cref="ArgumentException">A part is missing, the site is not https, or the severity is unknown.</exception>
    /// <exception cref="InvalidOperationException">No such organization, or no secret store to keep the keys in.</exception>
    public async Task<Webhook> SetConnectWiseAsync(
        string tenantSlug, string site, string companyId, string publicKey, string privateKey, string clientId,
        ConnectWiseSettings settings, string minSeverity, string? linkBase, string by,
        string payloadVersion = FindingVersion, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(by);
        ArgumentNullException.ThrowIfNull(settings);

        var payload = ParsePayloadVersion(payloadVersion);
        var apiBase = ConnectWiseClient.BaseFor(site);
        var link = linkBase is null ? null : ParseLinkBase(linkBase);
        var severity = ParseSeverity(minSeverity);

        foreach (var (name, value) in new[] { ("company id", companyId), ("public key", publicKey), ("private key", privateKey), ("clientId", clientId), ("board", settings.Board) })
        {
            if (string.IsNullOrWhiteSpace(value)) { throw new ArgumentException($"The ConnectWise {name} is missing."); }
        }

        var tenant = await EnsureTenantAsync(tenantSlug, ct).ConfigureAwait(false);
        var existing = await GetAsync(tenant.Slug, ConnectWiseKind, ct).ConfigureAwait(false);

        var credentialRef = CredentialRef.New(tenant.Slug, "connectwise");
        await Secrets.SetAsync(credentialRef, JsonSerializer.Serialize(new ConnectWiseCredential(
            apiBase.AbsoluteUri, companyId.Trim(), publicKey.Trim(), privateKey.Trim(), clientId.Trim())), ct).ConfigureAwait(false);

        var trimmed = settings with
        {
            Board = settings.Board.Trim(),
            Status = Clean(settings.Status),
            PriorityCritical = Clean(settings.PriorityCritical),
            PriorityWarning = Clean(settings.PriorityWarning),
        };

        await UpsertAsync(existing, tenant.Id, ConnectWiseKind, Destination(apiBase), credentialRef, severity,
            link?.AbsoluteUri.TrimEnd('/'), trimmed.ToJson(), payload, by, ct).ConfigureAwait(false);

        if (existing is not null && existing.CredentialRef != credentialRef)
        {
            await Secrets.RemoveAsync(existing.CredentialRef, ct).ConfigureAwait(false);
        }

        await new AuditLog(databasePath).RecordAsync(tenant.Id, by,
            existing is null ? "psa.set" : "psa.replace",
            $"ConnectWise at {Destination(apiBase)}, board '{trimmed.Board}', {severity} and above, {payload}", ct).ConfigureAwait(false);

        return (await GetAsync(tenant.Slug, ConnectWiseKind, ct).ConfigureAwait(false))!;
    }

    /// <summary>Stops sending to a destination, and forgets its address and keys. False when there was nothing to remove.</summary>
    public async Task<bool> RemoveAsync(string tenantSlug, string by, string kind = WebhookKind, CancellationToken ct = default)
    {
        var existing = await GetAsync(tenantSlug, kind, ct).ConfigureAwait(false);
        if (existing is null) { return false; }

        await using (var db = await OpenAsync(ct).ConfigureAwait(false))
        await using (var command = db.CreateCommand())
        {
            command.CommandText = "DELETE FROM webhooks WHERE id = $id";
            command.Parameters.AddWithValue("$id", existing.Id);
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await Secrets.RemoveAsync(existing.CredentialRef, ct).ConfigureAwait(false);
        await new AuditLog(databasePath).RecordAsync(existing.TenantId, by,
            existing.IsConnectWise ? "psa.remove" : "webhook.remove",
            $"was {existing.Destination}", ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>The full address and the signing key, or null when the store no longer has them.</summary>
    internal async Task<WebhookCredential?> CredentialAsync(Webhook webhook, CancellationToken ct)
    {
        var stored = await Secrets.GetAsync(webhook.CredentialRef, ct).ConfigureAwait(false);
        return stored is null ? null : JsonSerializer.Deserialize<WebhookCredential>(stored);
    }

    /// <summary>The four parts of the ConnectWise credential, or null when the store no longer has them.</summary>
    internal async Task<ConnectWiseCredential?> ConnectWiseCredentialAsync(Webhook webhook, CancellationToken ct)
    {
        var stored = await Secrets.GetAsync(webhook.CredentialRef, ct).ConfigureAwait(false);
        return stored is null ? null : JsonSerializer.Deserialize<ConnectWiseCredential>(stored);
    }

    /// <summary>
    /// HTTPS, or plain HTTP to this machine only - which is what a receiver
    /// on the same host, or one being tried out, looks like. Anything else
    /// would send client names and domains across a network in the clear.
    /// </summary>
    public static Uri ParseAddress(string url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException($"'{url}' is not an http or https address.");
        }

        if (uri.Scheme == Uri.UriSchemeHttp && !IsThisMachine(uri))
        {
            throw new ArgumentException(
                $"'{Destination(uri)}' is plain HTTP to another machine, which would send client names and domains unencrypted. Use https.");
        }

        return uri;
    }

    public static string ParseKind(string kind)
    {
        var clean = (kind ?? "").Trim().ToLowerInvariant();
        return Kinds.Contains(clean)
            ? clean
            : throw new ArgumentException($"'{kind}' is not a destination kind. Use one of: {string.Join(", ", Kinds)}.");
    }

    public static string ParsePayloadVersion(string payloadVersion)
    {
        var clean = (payloadVersion ?? "").Trim().ToLowerInvariant();
        return PayloadVersions.Contains(clean)
            ? clean
            : throw new ArgumentException($"'{payloadVersion}' is not a contract this sends. Use one of: {string.Join(", ", PayloadVersions)}.");
    }

    private static string ParseSeverity(string minSeverity)
    {
        var severity = (minSeverity ?? "").Trim().ToLowerInvariant();
        return Severities.Contains(severity)
            ? severity
            : throw new ArgumentException($"'{minSeverity}' is not a severity. Use one of: {string.Join(", ", Severities)}.");
    }

    private static Uri ParseLinkBase(string linkBase) =>
        Uri.TryCreate(linkBase.Trim(), UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? uri
            : throw new ArgumentException($"'{linkBase}' is not the dashboard's address, e.g. https://dmarc.example.com");

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool IsThisMachine(Uri uri) =>
        uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));

    private static string Destination(Uri uri) => $"{uri.Scheme}://{uri.Authority}";

    /// <summary>
    /// The organization, created when it is the built-in one and no report
    /// has made it yet: setting up where findings go is exactly what somebody
    /// does on install day. Any other is expected to have been created
    /// deliberately.
    /// </summary>
    private async Task<(string Id, string Slug)> EnsureTenantAsync(string tenantSlug, CancellationToken ct)
    {
        if (!Secrets.IsAvailable)
        {
            throw new InvalidOperationException($"The secret store cannot be used, so there is nowhere to keep the key. {Secrets.Description}");
        }

        var found = await TenantAsync(tenantSlug, ct).ConfigureAwait(false);
        if (found is null && string.Equals(tenantSlug.Trim(), ReportStore.DefaultTenantSlug, StringComparison.OrdinalIgnoreCase))
        {
            await new OrganizationStore(databasePath).CreateAsync("Local", ReportStore.DefaultTenantSlug, ct: ct).ConfigureAwait(false);
            found = await TenantAsync(tenantSlug, ct).ConfigureAwait(false);
        }
        return found ?? throw new InvalidOperationException($"There is no organization '{tenantSlug}'.");
    }

    private async Task UpsertAsync(
        Webhook? existing, string tenantId, string kind, string destination, string credentialRef, string severity,
        string? link, string? configJson, string payloadVersion, string by, CancellationToken ct)
    {
        var now = Stamp(_clock.GetUtcNow());
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = existing is null
            ? """
              INSERT INTO webhooks (id, tenant_id, kind, destination, credential_ref, min_severity, link_base, config_json,
                                    payload_version, created_at, created_by, updated_at)
              VALUES ($id, $tenant, $kind, $destination, $ref, $severity, $link, $config, $payload, $now, $by, $now)
              """
            : """
              UPDATE webhooks
              SET destination = $destination, credential_ref = $ref, min_severity = $severity,
                  link_base = $link, config_json = $config, payload_version = $payload,
                  updated_at = $now, last_error = NULL, last_error_at = NULL
              WHERE id = $id
              """;
        command.Parameters.AddWithValue("$payload", payloadVersion);
        command.Parameters.AddWithValue("$id", existing?.Id ?? Guid.NewGuid().ToString());
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$destination", destination);
        command.Parameters.AddWithValue("$ref", credentialRef);
        command.Parameters.AddWithValue("$severity", severity);
        command.Parameters.AddWithValue("$link", (object?)link ?? DBNull.Value);
        command.Parameters.AddWithValue("$config", (object?)configJson ?? DBNull.Value);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$by", by.Trim());
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private const string Select = """
        SELECT w.id, w.tenant_id, t.slug, w.destination, w.credential_ref, w.min_severity, w.link_base,
               w.created_at, w.created_by, w.last_delivered_at, w.last_error, w.last_error_at,
               w.kind, w.config_json, w.payload_version
        FROM webhooks w JOIN tenants t ON t.id = w.tenant_id
        """;

    private static async Task<IReadOnlyList<Webhook>> ReadAsync(SqliteCommand command, CancellationToken ct)
    {
        var result = new List<Webhook>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);

            result.Add(new Webhook
            {
                Id = reader.GetString(0),
                TenantId = reader.GetString(1),
                TenantSlug = reader.GetString(2),
                Destination = reader.GetString(3),
                CredentialRef = reader.GetString(4),
                MinSeverity = reader.GetString(5),
                LinkBase = Text(6),
                CreatedAt = ParseStamp(reader.GetString(7)) ?? DateTimeOffset.MinValue,
                CreatedBy = reader.GetString(8),
                LastDeliveredAt = Text(9) is { } delivered ? ParseStamp(delivered) : null,
                LastError = Text(10),
                LastErrorAt = Text(11) is { } failed ? ParseStamp(failed) : null,
                Kind = reader.GetString(12),
                ConnectWise = ConnectWiseSettings.FromJson(Text(13)),
                PayloadVersion = reader.GetString(14),
            });
        }
        return result;
    }

    private async Task<(string Id, string Slug)?> TenantAsync(string slug, CancellationToken ct)
    {
        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id, slug FROM tenants WHERE slug = $slug";
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? (reader.GetString(0), reader.GetString(1)) : null;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return db;
    }

    /// <summary>The format every other timestamp in the database is in, so they compare as strings.</summary>
    internal static string Stamp(DateTimeOffset when) =>
        when.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    internal static DateTimeOffset? ParseStamp(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value)
            ? value
            : null;
}
