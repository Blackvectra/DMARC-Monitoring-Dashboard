using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Forensic;

/// <summary>One stored failure report, as a page needs to show it.</summary>
public sealed record StoredFailure
{
    public required string Id { get; init; }
    public required string Domain { get; init; }
    public required string ClientName { get; init; }
    public required string ClientSlug { get; init; }

    public DateTimeOffset? ArrivedAt { get; init; }
    public string SourceIp { get; init; } = "";
    public string ReturnPath { get; init; } = "";
    public string HeaderFrom { get; init; } = "";
    public string Subject { get; init; } = "";
    public string AuthFailureType { get; init; } = "";
    public string DeliveryResult { get; init; } = "";
    public string DkimResult { get; init; } = "";
    public string SpfResult { get; init; } = "";
    public string ReportedBy { get; init; } = "";

    /// <summary>
    /// True when the message was delivered despite failing authentication.
    /// </summary>
    /// <remarks>
    /// The same rule the parser applies, repeated over what was stored: a
    /// receiver that did not say what it did with a failing message did not
    /// hold it back.
    /// </remarks>
    public bool WasDelivered =>
        DeliveryResult.Length == 0
        || DeliveryResult.Equals("none", StringComparison.OrdinalIgnoreCase)
        || DeliveryResult.Equals("delivered", StringComparison.OrdinalIgnoreCase);

    /// <summary>What this report is, in one sentence.</summary>
    /// <remarks>
    /// Written from the receiver's point of view rather than the record's,
    /// because the reader's question is never "what does auth_failure_type
    /// say" - it is whether somebody got a forged message.
    /// </remarks>
    public string Explain() =>
        (WasDelivered, AuthFailureType.ToLowerInvariant()) switch
        {
            (true, "dmarc") =>
                "A message claiming to be from this domain failed DMARC and was delivered anyway. "
              + "At p=none that is what the policy asks for, and it means somebody received it.",
            (false, "dmarc") =>
                "A message claiming to be from this domain failed DMARC and the receiver refused it. "
              + "This is the policy doing its job.",
            (true, "spf") =>
                "A message failed SPF and was delivered anyway. Either the sender is not in the record "
              + "or the domain is not yet refusing failures.",
            (false, "spf") =>
                "A message failed SPF and was refused.",
            (true, "dkim") =>
                "A message's DKIM signature did not verify and it was delivered anyway. Often a mail "
              + "gateway rewriting the message after it was signed rather than a forgery.",
            (false, "dkim") =>
                "A message's DKIM signature did not verify and it was refused.",
            (true, _) =>
                "A message failed authentication and was delivered anyway.",
            _ =>
                "A message failed authentication and was refused.",
        };
}

/// <summary>How many failure reports arrived, and from whom.</summary>
/// <param name="Total">Reports held in the window.</param>
/// <param name="Delivered">How many of them were about a message that reached somebody.</param>
/// <param name="Domains">How many domains they are spread across.</param>
/// <param name="Reporters">The receivers that sent them, most prolific first.</param>
public sealed record FailureSummary(
    int Total, int Delivered, int Domains, IReadOnlyList<string> Reporters);

/// <summary>
/// Reads stored DMARC failure reports.
///
/// Separate from the aggregate and TLS services for a reason that is not
/// tidiness: these rows are correspondence. Everything else in this product
/// counts messages, and this holds one - with the subject line and the headers
/// of mail a real person sent. So the summary a page needs and the content it
/// may only show some people are deliberately two different calls, and the
/// second one is not made unless somebody is allowed to make it.
/// </summary>
public sealed class ForensicReportService(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    /// <summary>Most reports listed at once.</summary>
    /// <remarks>
    /// Failure reports are rare enough that this is generous. It exists
    /// because the one estate where it is not rare is the one being actively
    /// forged, and that is not the moment to render ten thousand rows.
    /// </remarks>
    public const int MaxRows = 500;

    /// <param name="tenantId">One organization's, or null for every organization's.</param>
    /// <param name="clientSlug">One client's, for a customer's own login, or null.</param>
    public async Task<IReadOnlyList<StoredFailure>> ListAsync(
        int days = 30, string? tenantId = null, string? clientSlug = null, string? domain = null,
        CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        command.CommandText = """
            SELECT
              CAST(f.id AS TEXT), d.name, c.name, c.slug,
              COALESCE(f.arrival_date, f.received_at),
              COALESCE(f.source_ip, ''), COALESCE(f.return_path, ''), COALESCE(f.header_from, ''),
              COALESCE(f.subject, ''), COALESCE(f.auth_failure_type, ''), COALESCE(f.delivery_result, ''),
              COALESCE(f.dkim_result, ''), COALESCE(f.spf_result, ''), COALESCE(f.reported_by, '')
            FROM forensic_reports f
            JOIN domains d ON d.id = f.domain_id
            JOIN clients c ON c.id = f.client_id
            WHERE f.received_at >= $since
              AND ($tenant IS NULL OR f.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
              AND ($domain IS NULL OR d.name = $domain)
            ORDER BY COALESCE(f.arrival_date, f.received_at) DESC
            LIMIT $limit
            """;
        Bind(command, days, tenantId, clientSlug);

        // Bound here rather than in Bind: only this query filters by domain,
        // and a parameter declared for the summaries that their SQL never
        // mentions is one SQLite refuses the command over.
        command.Parameters.AddWithValue("$domain", (object?)Normalise(domain) ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", MaxRows);

        var results = new List<StoredFailure>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new StoredFailure
            {
                Id = reader.GetString(0),
                Domain = reader.GetString(1),
                ClientName = reader.GetString(2),
                ClientSlug = reader.GetString(3),
                ArrivedAt = ParseDate(reader.IsDBNull(4) ? null : reader.GetString(4)),
                SourceIp = reader.GetString(5),
                ReturnPath = reader.GetString(6),
                HeaderFrom = reader.GetString(7),
                Subject = reader.GetString(8),
                AuthFailureType = reader.GetString(9),
                DeliveryResult = reader.GetString(10),
                DkimResult = reader.GetString(11),
                SpfResult = reader.GetString(12),
                ReportedBy = reader.GetString(13),
            });
        }

        return results;
    }

    /// <summary>What arrived in the window, without reading any of the content.</summary>
    public async Task<FailureSummary> SummarizeAsync(
        int days = 30, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        int total = 0, delivered = 0, domains = 0;

        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT
                  COUNT(*),
                  SUM(CASE WHEN COALESCE(f.delivery_result, '') IN ('', 'none', 'delivered') THEN 1 ELSE 0 END),
                  COUNT(DISTINCT f.domain_id)
                FROM forensic_reports f
                JOIN clients c ON c.id = f.client_id
                WHERE f.received_at >= $since
                  AND ($tenant IS NULL OR f.tenant_id = $tenant)
                  AND ($client IS NULL OR c.slug = $client)
                """;
            Bind(command, days, tenantId, clientSlug);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                total = reader.IsDBNull(0) ? 0 : reader.GetInt32(0);
                delivered = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                domains = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
            }
        }

        var reporters = new List<string>();

        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT COALESCE(NULLIF(f.reported_by, ''), 'an unnamed receiver'), COUNT(*)
                FROM forensic_reports f
                JOIN clients c ON c.id = f.client_id
                WHERE f.received_at >= $since
                  AND ($tenant IS NULL OR f.tenant_id = $tenant)
                  AND ($client IS NULL OR c.slug = $client)
                GROUP BY 1
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """;
            Bind(command, days, tenantId, clientSlug);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                reporters.Add(reader.GetString(0));
            }
        }

        return new FailureSummary(total, delivered, domains, reporters);
    }

    /// <summary>
    /// The headers of the message one report is about, or null when there are
    /// none.
    /// </summary>
    /// <remarks>
    /// A separate call, taken separately, and scoped like every other. The
    /// caller is expected to have checked that this person may read message
    /// content and to have written a line in the audit log saying they did -
    /// which is the whole of the access control on the one thing in this
    /// product that is somebody's mail rather than a count of it.
    /// </remarks>
    public async Task<string?> HeadersAsync(
        string id, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        command.CommandText = """
            SELECT f.raw_headers
            FROM forensic_reports f
            JOIN clients c ON c.id = f.client_id
            WHERE f.id = $id
              AND ($tenant IS NULL OR f.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)Normalise(clientSlug) ?? DBNull.Value);

        var headers = await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
        return string.IsNullOrWhiteSpace(headers) ? null : headers;
    }

    private static void Bind(
        SqliteCommand command, int days, string? tenantId, string? clientSlug)
    {
        command.Parameters.AddWithValue(
            "$since",
            DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
                .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)Normalise(clientSlug) ?? DBNull.Value);
    }

    private static string? Normalise(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();

    private static DateTimeOffset? ParseDate(string? value) =>
        value is not null && DateTime.TryParse(
            value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? new DateTimeOffset(parsed, TimeSpan.Zero)
            : null;
}
