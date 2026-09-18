using System.Globalization;
using System.Text.Json;
using Azure.Identity;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Which provider holds a zone, and the non-secret coordinates for reaching it.
/// </summary>
/// <param name="Domain">The domain it applies to, or null for every domain of the client.</param>
/// <param name="Settings">Zone id, subscription, resource group: whatever the provider needs that is not a secret.</param>
/// <param name="CredentialRef">Pointer into the secret store, or null for a provider that needs none.</param>
public sealed record DnsProviderConfig(
    string Id,
    string ClientSlug,
    string? Domain,
    string Provider,
    IReadOnlyDictionary<string, string> Settings,
    string? CredentialRef,
    DateTimeOffset? LastVerifiedAt,
    string? LastError);

/// <summary>
/// The dns_provider_configs table, and the providers built from it.
///
/// A config can be for one domain or for every domain of a client, and the
/// specific one wins. Secrets go through the store on the way in and never
/// come back out of here as anything but a provider ready to use.
/// </summary>
public sealed class DnsProviderConfigs(string databasePath, ISecretStore secrets, Func<HttpClient>? httpFactory = null)
{
    public static readonly IReadOnlyList<string> Providers = ["cloudflare", "azuredns", "manual"];

    private readonly string _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
    private readonly Func<HttpClient> _http = httpFactory ?? (() => new HttpClient());

    public ISecretStore Secrets { get; } = secrets;

    /// <summary>
    /// Stores a provider for a client or one of its domains, and its secret
    /// if it has one. Replaces any existing config with the same scope.
    /// </summary>
    /// <remarks>
    /// The secret is accepted here once, handed to the store, and only its
    /// ref is written to the row. A replaced config has its old secret
    /// removed from the store so nothing is left behind unreferenced.
    /// </remarks>
    public async Task<DnsProviderConfig> SetAsync(
        string clientSlug, string? domain, string provider,
        IReadOnlyDictionary<string, string> settings, string? secret, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentNullException.ThrowIfNull(settings);

        var kind = provider.Trim().ToLowerInvariant();
        if (!Providers.Contains(kind))
        {
            throw new ArgumentException($"'{provider}' is not a provider this knows. One of: {string.Join(", ", Providers)}.", nameof(provider));
        }

        foreach (var required in RequiredSettings(kind))
        {
            if (!settings.TryGetValue(required, out var v) || string.IsNullOrWhiteSpace(v))
            {
                throw new ArgumentException($"{kind} needs '{required}'.", nameof(settings));
            }
        }

        if (kind == "cloudflare" && string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException("cloudflare needs an API token. Use a token scoped to Zone:DNS:Edit on this zone, never the Global API Key.", nameof(secret));
        }

        if (!string.IsNullOrEmpty(secret) && !Secrets.IsAvailable)
        {
            throw new InvalidOperationException($"The secret store is not available, so nothing was saved. {Secrets.Description}");
        }

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var (tenantId, tenantSlug, clientId) = await ClientAsync(db, clientSlug, ct).ConfigureAwait(false)
            ?? throw new ArgumentException($"No client filed as '{clientSlug}'.", nameof(clientSlug));

        string? domainId = null;
        var domainName = domain?.Trim().TrimEnd('.').ToLowerInvariant();
        if (domainName is not null)
        {
            domainId = await DomainIdAsync(db, clientId, domainName, ct).ConfigureAwait(false)
                ?? throw new ArgumentException($"{domainName} is not a domain of '{clientSlug}'.", nameof(domain));
        }

        // Whatever was there for this scope goes, secret included.
        foreach (var old in await ListAsync(db, clientId, domainId, ct).ConfigureAwait(false))
        {
            if (old.CredentialRef is not null) { await Secrets.RemoveAsync(old.CredentialRef, ct).ConfigureAwait(false); }
            await ExecAsync(db, "DELETE FROM dns_provider_configs WHERE id = $id", ct, ("$id", old.Id)).ConfigureAwait(false);
        }

        string? credentialRef = null;
        if (!string.IsNullOrEmpty(secret))
        {
            credentialRef = CredentialRef.New(tenantSlug, kind);
            await Secrets.SetAsync(credentialRef, secret, ct).ConfigureAwait(false);
        }

        var id = Guid.NewGuid().ToString("N");
        var now = Iso(DateTimeOffset.UtcNow);
        await ExecAsync(db, """
            INSERT INTO dns_provider_configs
                (id, tenant_id, client_id, domain_id, provider, config_json, credential_ref, is_enabled, created_at, updated_at)
            VALUES ($id, $tenant, $client, $domain, $provider, $config, $ref, 1, $now, $now)
            """, ct,
            ("$id", id), ("$tenant", tenantId), ("$client", clientId), ("$domain", (object?)domainId ?? DBNull.Value),
            ("$provider", kind), ("$config", JsonSerializer.Serialize(settings)),
            ("$ref", (object?)credentialRef ?? DBNull.Value), ("$now", now)).ConfigureAwait(false);

        return new DnsProviderConfig(id, clientSlug, domainName, kind, settings, credentialRef, null, null);
    }

    public async Task<bool> RemoveAsync(string clientSlug, string? domain, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var client = await ClientAsync(db, clientSlug, ct).ConfigureAwait(false);
        if (client is null) { return false; }

        string? domainId = null;
        if (domain is not null)
        {
            domainId = await DomainIdAsync(db, client.Value.ClientId, domain.Trim().ToLowerInvariant(), ct).ConfigureAwait(false);
            if (domainId is null) { return false; }
        }

        var removed = false;
        foreach (var old in await ListAsync(db, client.Value.ClientId, domainId, ct).ConfigureAwait(false))
        {
            if (old.CredentialRef is not null && Secrets.IsAvailable)
            {
                await Secrets.RemoveAsync(old.CredentialRef, ct).ConfigureAwait(false);
            }
            await ExecAsync(db, "DELETE FROM dns_provider_configs WHERE id = $id", ct, ("$id", old.Id)).ConfigureAwait(false);
            removed = true;
        }
        return removed;
    }

    /// <summary>Records that the provider was just tried, and how it went.</summary>
    public async Task MarkVerifiedAsync(string configId, string? error, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await ExecAsync(db,
            "UPDATE dns_provider_configs SET last_verified_at = $now, last_error = $err, updated_at = $now WHERE id = $id", ct,
            ("$now", Iso(DateTimeOffset.UtcNow)), ("$err", (object?)error ?? DBNull.Value), ("$id", configId)).ConfigureAwait(false);
    }

    /// <summary>Every configured provider, for the settings page. Refs only; never a secret.</summary>
    public async Task<IReadOnlyList<DnsProviderConfig>> ListAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return await ListAsync(db, null, null, ct).ConfigureAwait(false);
    }

    /// <summary>The config that applies to a domain: its own, else its client's, else null.</summary>
    public async Task<DnsProviderConfig?> ForDomainAsync(string domain, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT p.id, c.slug, d2.name, p.provider, p.config_json, p.credential_ref, p.last_verified_at, p.last_error
            FROM domains d
            JOIN dns_provider_configs p ON p.client_id = d.client_id AND (p.domain_id = d.id OR p.domain_id IS NULL)
            JOIN clients c ON c.id = p.client_id
            LEFT JOIN domains d2 ON d2.id = p.domain_id
            WHERE d.name = $name AND p.is_enabled = 1
            ORDER BY p.domain_id IS NULL
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$name", name);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? Row(reader) : null;
    }

    /// <summary>
    /// A provider ready to use for a domain. The manual provider when nothing
    /// is configured, so a plan can always be made and shown even where it
    /// cannot be applied.
    /// </summary>
    public async Task<IDnsProvider> ProviderForAsync(string domain, CancellationToken ct = default)
    {
        var config = await ForDomainAsync(domain, ct).ConfigureAwait(false);
        return config is null ? new ManualDnsProvider() : await BuildAsync(config, ct).ConfigureAwait(false);
    }

    public async Task<IDnsProvider> BuildAsync(DnsProviderConfig config, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(config);

        string? secret = null;
        if (config.CredentialRef is not null)
        {
            secret = await Secrets.GetAsync(config.CredentialRef, ct).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    $"The {config.Provider} credential for {config.Domain ?? config.ClientSlug} is referenced but not in the secret store. "
                    + "Set the provider again to re-enter it.");
        }

        switch (config.Provider)
        {
            case "cloudflare":
                return new CloudflareDnsProvider(_http(), config.Settings["zone_id"], secret!);

            case "azuredns":
                // A client secret is optional: without one the process's own
                // identity is used, which on a server is a managed identity
                // and on a desk is whoever is signed in to az.
                var tenant = config.Settings.GetValueOrDefault("tenant_id");
                var app = config.Settings.GetValueOrDefault("client_id");
                Azure.Core.TokenCredential credential = secret is not null && tenant is not null && app is not null
                    ? new ClientSecretCredential(tenant, app, secret)
                    : new DefaultAzureCredential();
                return new AzureDnsProvider(_http(), credential,
                    config.Settings["subscription_id"], config.Settings["resource_group"], config.Settings["zone"]);

            default:
                return new ManualDnsProvider();
        }
    }

    public static IReadOnlyList<string> RequiredSettings(string provider) => provider switch
    {
        "cloudflare" => ["zone_id"],
        "azuredns" => ["subscription_id", "resource_group", "zone"],
        _ => [],
    };

    private static async Task<List<DnsProviderConfig>> ListAsync(SqliteConnection db, string? clientId, string? domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT p.id, c.slug, d.name, p.provider, p.config_json, p.credential_ref, p.last_verified_at, p.last_error
            FROM dns_provider_configs p
            JOIN clients c ON c.id = p.client_id
            LEFT JOIN domains d ON d.id = p.domain_id
            WHERE ($client IS NULL OR p.client_id = $client)
              AND ($client IS NULL OR ($domain IS NULL AND p.domain_id IS NULL) OR p.domain_id = $domain)
            ORDER BY c.slug, d.name
            """;
        command.Parameters.AddWithValue("$client", (object?)clientId ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)domainId ?? DBNull.Value);

        var result = new List<DnsProviderConfig>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { result.Add(Row(reader)); }
        return result;
    }

    private static DnsProviderConfig Row(SqliteDataReader r)
    {
        var settings = r.IsDBNull(4)
            ? new Dictionary<string, string>()
            : JsonSerializer.Deserialize<Dictionary<string, string>>(r.GetString(4)) ?? [];

        DateTimeOffset? verified = !r.IsDBNull(6) && DateTime.TryParse(r.GetString(6), CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var when) ? when : null;

        return new DnsProviderConfig(
            r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2), r.GetString(3),
            settings, r.IsDBNull(5) ? null : r.GetString(5), verified, r.IsDBNull(7) ? null : r.GetString(7));
    }

    private static async Task<(string TenantId, string TenantSlug, string ClientId)?> ClientAsync(SqliteConnection db, string slug, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT t.id, t.slug, c.id FROM clients c JOIN tenants t ON t.id = c.tenant_id
            WHERE c.slug = $slug AND c.deleted_at IS NULL LIMIT 1
            """;
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }
        return (reader.GetString(0), reader.GetString(1), reader.GetString(2));
    }

    private static async Task<string?> DomainIdAsync(SqliteConnection db, string clientId, string domain, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id FROM domains WHERE client_id = $client AND name = $name AND deleted_at IS NULL LIMIT 1";
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$name", domain);
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
    }

    private static async Task ExecAsync(SqliteConnection db, string sql, CancellationToken ct, params (string, object)[] parameters)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) { command.Parameters.AddWithValue(name, value); }
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
