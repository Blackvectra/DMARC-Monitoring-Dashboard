using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// Small facts about a client that are the organization's to keep, in the
/// organization's database: client_settings.
/// </summary>
/// <remarks>
/// A key/value table rather than a column per fact, because the facts are few
/// and arrive one integration at a time. The first is which company a client
/// is in the organization's PSA - set by a person naming the company, never
/// guessed from a name: a slug that happens to resemble a company identifier
/// would file one customer's ticket on another customer's account.
/// </remarks>
public sealed class ClientSettingsStore(string databasePath)
{
    /// <summary>The client's company id in ConnectWise PSA.</summary>
    public const string ConnectWiseCompany = "connectwise.company_id";

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
        Pooling = false,
    }.ToString();

    /// <summary>One setting of one client, or null when it has none.</summary>
    public async Task<string?> GetAsync(string clientId, string key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT value FROM client_settings WHERE client_id = $client AND key = $key";
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$key", key);
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
    }

    /// <summary>One setting across an organization's clients, by client id. Clients without it are absent.</summary>
    public async Task<IReadOnlyDictionary<string, string>> ForOrganizationAsync(string tenantId, string key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT client_id, value FROM client_settings WHERE tenant_id = $tenant AND key = $key";
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$key", key);

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result[reader.GetString(0)] = reader.GetString(1);
        }
        return result;
    }

    /// <summary>
    /// Sets a client's setting, or removes it when <paramref name="value"/> is null.
    /// </summary>
    /// <returns>False when the organization has no such client.</returns>
    public async Task<bool> SetAsync(string tenantSlug, string clientSlug, string key, string? value, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        await using var db = await OpenAsync(ct).ConfigureAwait(false);

        string clientId, tenantId;
        await using (var find = db.CreateCommand())
        {
            find.CommandText = """
                SELECT c.id, c.tenant_id
                FROM clients c JOIN tenants t ON t.id = c.tenant_id
                WHERE t.slug = $org AND c.slug = $slug AND c.deleted_at IS NULL
                """;
            find.Parameters.AddWithValue("$org", tenantSlug.Trim().ToLowerInvariant());
            find.Parameters.AddWithValue("$slug", clientSlug.Trim().ToLowerInvariant());
            await using var reader = await find.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return false; }
            clientId = reader.GetString(0);
            tenantId = reader.GetString(1);
        }

        await using var command = db.CreateCommand();
        if (value is null)
        {
            command.CommandText = "DELETE FROM client_settings WHERE client_id = $client AND key = $key";
        }
        else
        {
            command.CommandText = """
                INSERT INTO client_settings (tenant_id, client_id, key, value, updated_at)
                VALUES ($tenant, $client, $key, $value, $now)
                ON CONFLICT (client_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """;
            command.Parameters.AddWithValue("$tenant", tenantId);
            command.Parameters.AddWithValue("$value", value.Trim());
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        }
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$key", key);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        return true;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return db;
    }
}
