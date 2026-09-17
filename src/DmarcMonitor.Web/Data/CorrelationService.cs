using System.Globalization;

namespace DmarcMonitor.Web.Data;

/// <summary>A sending source seen failing authentication, possibly across several clients.</summary>
public sealed record FailingSource
{
    public required string SourceIp { get; init; }
    public long FailedMessages { get; init; }
    public IReadOnlyList<string> Domains { get; init; } = [];
    public IReadOnlyList<string> Clients { get; init; } = [];
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>
    /// Domains this source authenticated FOR, when it authenticated anything.
    /// </summary>
    /// <remarks>
    /// The difference between a misconfigured service and an impersonator. A
    /// source that authenticated for its own domain is almost always a real
    /// provider somebody set up without aligning it. A source that
    /// authenticated nothing at all, for anyone, is what impersonation looks
    /// like.
    /// </remarks>
    public IReadOnlyList<string> AuthenticatedFor { get; init; } = [];

    public int DomainCount => Domains.Count;
    public int ClientCount => Clients.Count;

    /// <summary>Seen against more than one client. Only a multi-client platform can see this.</summary>
    public bool IsCrossClient => ClientCount > 1;

    public bool AuthenticatedNothing => AuthenticatedFor.Count == 0;

    /// <summary>
    /// What this most likely is. Deliberately cautious: calling a customer's
    /// own marketing platform an attacker is how an operator blocks their
    /// client's invoices.
    /// </summary>
    public SourceVerdict Verdict =>
        !AuthenticatedNothing ? SourceVerdict.Misconfigured
        : IsCrossClient ? SourceVerdict.CrossClientImpersonation
        : SourceVerdict.Unauthenticated;
}

public enum SourceVerdict
{
    /// <summary>Authenticated for its own domain. A real service, set up unaligned.</summary>
    Misconfigured,

    /// <summary>Authenticated nothing, seen against one domain.</summary>
    Unauthenticated,

    /// <summary>Authenticated nothing, working through several unrelated clients.</summary>
    CrossClientImpersonation,
}

/// <summary>
/// Finds sending sources that fail authentication, and how many clients each
/// one is hitting.
///
/// This is the query a single-tenant tool cannot run. dmarcian shows a domain
/// owner their own reports; it never sees another company's data, so it cannot
/// notice that the same source is working through several businesses. An MSP
/// watching thirteen domains can, and the correlation is the strongest signal
/// in the dataset: one unauthenticated source against one domain is noise,
/// while the same source against three unrelated clients is somebody running a
/// campaign.
/// </summary>
public sealed class CorrelationService(ReportStoreConnection connection)
{
    private readonly ReportStoreConnection _connection = connection;

    public async Task<IReadOnlyList<FailingSource>> GetFailingSourcesAsync(
        int days = 30, int limit = 200, CancellationToken ct = default)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = await _connection.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        // Overrides are excluded. A mailing list or forwarder breaking
        // authentication is expected behaviour, and including it would bury
        // the real findings under traffic nobody should act on.
        command.CommandText = """
            SELECT
              r.source_ip,
              SUM(r.message_count)                                   AS failed,
              GROUP_CONCAT(DISTINCT d.name)                          AS domains,
              GROUP_CONCAT(DISTINCT c.name)                          AS clients,
              MAX(r.date_begin)                                      AS last_seen,
              GROUP_CONCAT(DISTINCT
                CASE WHEN r.spf_auth_result = 'pass' THEN COALESCE(r.spf_domain, '') ELSE '' END
                || '|' ||
                CASE WHEN r.dkim_auth_result = 'pass' THEN COALESCE(r.dkim_domain, '') ELSE '' END) AS auth
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            JOIN clients c ON c.id = r.client_id
            WHERE r.dmarc_result = 'fail'
              AND r.date_begin >= $since
              AND (r.override_reason IS NULL OR r.override_reason = '')
            GROUP BY r.source_ip
            ORDER BY COUNT(DISTINCT r.client_id) DESC, failed DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$since", since);
        command.Parameters.AddWithValue("$limit", limit);

        var results = new List<FailingSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var domains = Split(reader.IsDBNull(2) ? "" : reader.GetString(2));
            var clients = Split(reader.IsDBNull(3) ? "" : reader.GetString(3));

            DateTimeOffset? lastSeen = null;
            if (!reader.IsDBNull(4) &&
                DateTime.TryParse(reader.GetString(4), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                lastSeen = new DateTimeOffset(parsed, TimeSpan.Zero);
            }

            results.Add(new FailingSource
            {
                SourceIp = reader.GetString(0),
                FailedMessages = reader.IsDBNull(1) ? 0 : reader.GetInt64(1),
                Domains = domains,
                Clients = clients,
                LastSeen = lastSeen,
                AuthenticatedFor = ParseAuthDomains(reader.IsDBNull(5) ? "" : reader.GetString(5)),
            });
        }

        return results;
    }

    private static List<string> Split(string value) =>
        [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Distinct(StringComparer.OrdinalIgnoreCase)
                 .OrderBy(v => v, StringComparer.Ordinal)];

    /// <summary>
    /// Unpacks the "spf|dkim" pairs the query concatenates, dropping the empty
    /// halves. A source with no authenticated domain at all is the signal that
    /// separates impersonation from misconfiguration, so an empty string must
    /// not survive as if it were a domain.
    /// </summary>
    private static List<string> ParseAuthDomains(string concatenated)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pair in concatenated.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var part in pair.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!string.IsNullOrWhiteSpace(part)) { domains.Add(part); }
            }
        }

        return [.. domains.OrderBy(d => d, StringComparer.Ordinal)];
    }
}
