using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// Assembles a client's monthly report from stored data.
///
/// Every figure comes from the database, including "what we did", which is
/// read from the DNS change audit trail rather than typed by hand. An MSP who
/// has to remember what they changed for a client six weeks ago will either
/// leave the section out or overstate it, and both are worse than a short,
/// accurate list.
/// </summary>
public sealed class ClientReportBuilder(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    public async Task<ClientReport?> BuildAsync(
        string clientSlug, ReportPeriod period, string providerName = "Your IT provider", CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);
        ArgumentNullException.ThrowIfNull(period);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var client = await GetClientAsync(db, clientSlug, ct).ConfigureAwait(false);
        if (client is null) { return null; }

        var (clientId, clientName) = client.Value;

        var domains = await GetDomainHealthAsync(db, clientId, period, ct).ConfigureAwait(false);
        var sources = await GetSourcesAsync(db, clientId, period, ct).ConfigureAwait(false);
        var changes = await GetChangesAsync(db, clientId, period, ct).ConfigureAwait(false);
        var current = await GetTotalsAsync(db, clientId, period.Start, period.End, ct).ConfigureAwait(false);
        var previous = await GetTotalsAsync(db, clientId, period.PreviousStart, period.PreviousEnd, ct).ConfigureAwait(false);

        return new ClientReport
        {
            ClientName = clientName,
            ProviderName = providerName,
            Period = period,
            Domains = domains,
            Sources = sources,
            Changes = changes,
            Messages = current.Messages,
            Passing = current.Passing,
            Failing = current.Messages - current.Passing,
            PreviousMessages = previous.Messages,
            PreviousPassing = previous.Passing,
        };
    }

    /// <summary>Every client that could be reported on, for a "generate all" run.</summary>
    public async Task<IReadOnlyList<(string Slug, string Name)>> GetClientsAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = "SELECT slug, name FROM clients WHERE deleted_at IS NULL ORDER BY name";

        var results = new List<(string, string)>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add((reader.GetString(0), reader.GetString(1)));
        }
        return results;
    }

    private static async Task<(string Id, string Name)?> GetClientAsync(
        SqliteConnection db, string slug, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id, name FROM clients WHERE slug = $slug AND deleted_at IS NULL LIMIT 1";
        command.Parameters.AddWithValue("$slug", slug);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }
        return (reader.GetString(0), reader.GetString(1));
    }

    private static async Task<(long Messages, long Passing)> GetTotalsAsync(
        SqliteConnection db, string clientId, DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT COALESCE(SUM(message_count), 0),
                   COALESCE(SUM(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0)
            FROM aggregate_records
            WHERE client_id = $client AND date_begin >= $from AND date_begin <= $to
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(from));
        command.Parameters.AddWithValue("$to", Iso(to));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return (0, 0); }
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private static async Task<List<ReportDomainHealth>> GetDomainHealthAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Left join so a domain with no traffic still appears. A client's
        // domain that sent nothing is worth saying out loud, not omitting.
        command.CommandText = """
            SELECT d.name,
                   COALESCE(SUM(r.message_count), 0),
                   COALESCE(SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count END), 0),
                   (SELECT ar.policy_p    FROM aggregate_reports ar WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_sp   FROM aggregate_reports ar WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_pct  FROM aggregate_reports ar WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT ar.policy_adkim FROM aggregate_reports ar WHERE ar.domain_id = d.id ORDER BY ar.date_end DESC LIMIT 1),
                   (SELECT t.policy_mode  FROM tls_reports t WHERE t.domain_id = d.id ORDER BY t.date_end DESC LIMIT 1)
            FROM domains d
            LEFT JOIN aggregate_records r
                   ON r.domain_id = d.id AND r.date_begin >= $from AND r.date_begin <= $to
            WHERE d.client_id = $client AND d.deleted_at IS NULL
            GROUP BY d.id, d.name
            ORDER BY d.name
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportDomainHealth>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new ReportDomainHealth
            {
                Domain = reader.GetString(0),
                Messages = reader.GetInt64(1),
                Passing = reader.GetInt64(2),
                Policy = reader.IsDBNull(3) ? "none" : reader.GetString(3),
                SubdomainPolicy = reader.IsDBNull(4) ? "" : reader.GetString(4),
                Pct = reader.IsDBNull(5) ? 100 : reader.GetInt32(5),
                StrictAlignment = !reader.IsDBNull(6) && reader.GetString(6) == "s",
                MtaStsMode = reader.IsDBNull(7) ? "" : reader.GetString(7),
            });
        }
        return results;
    }

    private static async Task<List<ReportSource>> GetSourcesAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // The correlated subquery counts OTHER clients the same source was
        // seen failing against. That is the part of this report no
        // single-tenant tool can produce, and it belongs in front of the
        // client rather than only in the operator's console.
        command.CommandText = """
            SELECT r.source_ip,
                   SUM(r.message_count),
                   SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count ELSE 0 END),
                   GROUP_CONCAT(DISTINCT d.name),
                   -- Only the FAILING rows. This value decides whether the
                   -- client is told "a service of yours needs correcting" or
                   -- "somebody sent mail as you", so it has to describe the
                   -- mail that failed, not the mail that worked. Taken across
                   -- every row, a source that authenticates legitimately most
                   -- of the time and fails once with no authentication at all
                   -- is labelled a misconfigured service of the client's own,
                   -- and the one message that was actually unprovable
                   -- disappears into a maintenance note.
                   COALESCE(NULLIF(GROUP_CONCAT(DISTINCT
                     CASE WHEN r.dmarc_result = 'fail' AND r.dkim_auth_result = 'pass' THEN r.dkim_domain
                          WHEN r.dmarc_result = 'fail' AND r.spf_auth_result  = 'pass' THEN r.spf_domain END), ''), ''),
                   (SELECT COUNT(DISTINCT o.client_id)
                      FROM aggregate_records o
                     WHERE o.source_ip = r.source_ip
                       AND o.client_id <> $client
                       AND o.dmarc_result = 'fail')
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE r.client_id = $client AND r.date_begin >= $from AND r.date_begin <= $to
              AND (r.override_reason IS NULL OR r.override_reason = '')
            GROUP BY r.source_ip
            ORDER BY SUM(r.message_count) DESC
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var messages = reader.GetInt64(1);
            var passing = reader.GetInt64(2);

            results.Add(new ReportSource
            {
                SourceIp = reader.GetString(0),
                Messages = messages,
                Passing = passing,
                Failing = messages - passing,
                Domains = reader.IsDBNull(3) ? [] : [.. reader.GetString(3).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
                AuthenticatedFor = reader.IsDBNull(4) ? "" : reader.GetString(4),
                OtherClientsAffected = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
            });
        }
        return results;
    }

    /// <summary>
    /// What was actually changed for this client, from the audit trail.
    /// </summary>
    /// <remarks>
    /// Rolled-back changes are included and labelled. Hiding them would make
    /// the report a sales document rather than a record: a change that was
    /// applied and then reverted is exactly the kind of thing a client should
    /// hear from their provider rather than discover.
    /// </remarks>
    private static async Task<List<ReportChange>> GetChangesAsync(
        SqliteConnection db, string clientId, ReportPeriod period, CancellationToken ct)
    {
        // The remediation tables exist in the schema but are written by the
        // apply path, which may not have run. A client with no changes is
        // normal, not an error.
        if (!await TableExistsAsync(db, "dns_changes", ct).ConfigureAwait(false)) { return []; }

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT record_name, record_type, previous_value, new_value, reason, applied_at, rolled_back_at
            FROM dns_changes
            WHERE client_id = $client AND applied_at >= $from AND applied_at <= $to
            ORDER BY applied_at
            """;
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$from", Iso(period.Start));
        command.Parameters.AddWithValue("$to", Iso(period.End));

        var results = new List<ReportChange>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            DateTimeOffset appliedAt = default;
            if (!reader.IsDBNull(5) &&
                DateTime.TryParse(reader.GetString(5), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                appliedAt = new DateTimeOffset(parsed, TimeSpan.Zero);
            }

            results.Add(new ReportChange
            {
                RecordName = reader.GetString(0),
                RecordType = reader.GetString(1),
                PreviousValue = reader.IsDBNull(2) ? "" : reader.GetString(2),
                NewValue = reader.IsDBNull(3) ? "" : reader.GetString(3),
                Reason = reader.IsDBNull(4) ? "" : reader.GetString(4),
                AppliedAt = appliedAt,
                WasRolledBack = !reader.IsDBNull(6),
            });
        }
        return results;
    }

    private static async Task<bool> TableExistsAsync(SqliteConnection db, string name, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name";
        command.Parameters.AddWithValue("$name", name);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
