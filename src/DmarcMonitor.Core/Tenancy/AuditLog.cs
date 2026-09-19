using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tenancy;

/// <summary>One thing somebody did.</summary>
public sealed record AuditEntry(DateTimeOffset At, string Actor, string Action, string? Detail, string? TenantId);

/// <summary>
/// Who did what, for the settings page and for anybody asking afterwards.
///
/// Not the DNS change trail, which dns_changes keeps in full with before and
/// after values; this is the rest: organisations, groups, clients, providers,
/// imports. Every hosted DMARC product with more than one login has one of
/// these, and the question it answers - "who moved that domain?" - comes up
/// the week after two organisations share an install.
/// </summary>
public sealed class AuditLog(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();

    /// <param name="tenantId">The organisation it concerns, or null for the platform.</param>
    public async Task RecordAsync(string? tenantId, string actor, string action, string? detail = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO audit_log (tenant_id, at, actor, action, detail) VALUES ($tenant, $at, $actor, $action, $detail)";
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$actor", string.IsNullOrWhiteSpace(actor) ? "unknown" : actor.Trim());
        command.Parameters.AddWithValue("$action", action.Trim());
        command.Parameters.AddWithValue("$detail", (object?)(string.IsNullOrWhiteSpace(detail) ? null : detail.Trim()) ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Newest first. One organisation's entries plus the platform's, or everything when unscoped.</summary>
    public async Task<IReadOnlyList<AuditEntry>> ListAsync(string? tenantId = null, int limit = 50, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT at, actor, action, detail, tenant_id FROM audit_log
            WHERE ($tenant IS NULL OR tenant_id = $tenant OR tenant_id IS NULL)
            ORDER BY id DESC LIMIT $limit
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", limit);

        var result = new List<AuditEntry>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var at = DateTime.TryParse(reader.GetString(0), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
                ? new DateTimeOffset(parsed, TimeSpan.Zero)
                : DateTimeOffset.MinValue;
            result.Add(new AuditEntry(at, reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4)));
        }
        return result;
    }
}
