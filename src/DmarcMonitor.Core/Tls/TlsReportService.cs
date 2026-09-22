using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tls;

/// <summary>One domain's transport security, as the receivers reported it.</summary>
public sealed record TlsDomainSummary
{
    public required string Domain { get; init; }
    public required string ClientName { get; init; }
    public required string ClientSlug { get; init; }

    /// <summary>Sessions that negotiated TLS as the policy required.</summary>
    public long Successful { get; init; }

    /// <summary>Sessions that did not, and were reported.</summary>
    public long Failed { get; init; }

    public long Sessions => Successful + Failed;

    /// <summary>
    /// The strongest mode any reporter said it fetched during the window.
    /// </summary>
    /// <remarks>
    /// As the RECEIVER fetched it, not whatever DNS says today. This is the
    /// field that decides whether TLS was actually enforced: a domain in
    /// testing has its failures reported and its mail delivered over
    /// plaintext anyway, so it can sit there for years generating perfectly
    /// clean reports while being no better protected than a domain with no
    /// policy at all.
    /// </remarks>
    public string PolicyMode { get; init; } = "unknown";

    /// <summary>How many reporting organizations sent anything for this domain.</summary>
    public int Reporters { get; init; }

    public DateTimeOffset? LastReport { get; init; }

    public double SuccessRate =>
        Sessions == 0 ? 0 : Math.Round(Successful * 100.0 / Sessions, 1);

    /// <summary>
    /// Protected only when a policy is being enforced AND nothing is failing.
    /// </summary>
    /// <remarks>
    /// Both halves are needed and each is useless alone. Enforcing with
    /// failures means mail is being refused; clean reports in testing mode
    /// means nothing was ever refused and the clean sheet proves nothing.
    /// </remarks>
    public bool IsProtected =>
        PolicyMode.Equals("enforce", StringComparison.OrdinalIgnoreCase) && Failed == 0;

    /// <summary>
    /// Enforcing, and losing mail because of it. The only urgent state here.
    /// </summary>
    public bool IsLosingMail =>
        PolicyMode.Equals("enforce", StringComparison.OrdinalIgnoreCase) && Failed > 0;
}

/// <summary>Why sessions failed, grouped the way somebody would fix them.</summary>
public sealed record TlsFailure
{
    public required string Domain { get; init; }

    /// <summary>starttls-not-supported, certificate-expired, and the rest of RFC 8460.</summary>
    public required string ResultType { get; init; }

    public string ReceivingMx { get; init; } = "";
    public long Sessions { get; init; }
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>What the result type means, and who has to fix it.</summary>
    /// <remarks>
    /// Almost every one of these is the RECEIVING side's problem, which is
    /// the single most useful thing to say: an operator seeing failures
    /// against their own domain reasonably assumes they caused them, and
    /// spends a morning on a certificate that was never theirs.
    /// </remarks>
    public string Explain() => ResultType.ToLowerInvariant() switch
    {
        "starttls-not-supported" =>
            "The receiving server did not offer STARTTLS at all. That is their mail server, not yours, "
          + "and until they fix it your policy will keep refusing to deliver to them.",
        "certificate-expired" =>
            "The receiving server's certificate had expired. Theirs to renew.",
        "certificate-not-trusted" =>
            "The receiving server's certificate did not chain to a trusted root — often a self-signed "
          + "or internal certificate on a mail server that is reachable from the internet.",
        "certificate-host-mismatch" =>
            "The certificate did not cover the hostname in the MX record. Usually a server behind a "
          + "name it was not issued for.",
        "validation-failure" =>
            "TLS could not be established, without a more specific reason. Worth checking whether the "
          + "MX host is reachable at all.",
        "sts-policy-fetch-error" =>
            "The sender could not fetch your MTA-STS policy. This one IS yours: the policy host has to "
          + "answer over HTTPS with a certificate valid for it.",
        "sts-policy-invalid" or "sts-policy-fetch-invalid" =>
            "Your MTA-STS policy was fetched but did not parse. This one is yours to correct.",
        "sts-webpki-invalid" =>
            "The certificate on your policy host did not validate. Yours: senders will not accept a "
          + "policy served over a certificate they cannot verify.",
        "tlsa-invalid" or "dnssec-invalid" or "dane-required" =>
            "A DANE failure. Relevant only if this domain publishes TLSA records.",
        _ => "An unrecognised failure type. The raw report has the detail.",
    };

    /// <summary>Whether this is the reporting domain's own fault to fix.</summary>
    public bool IsOurs => ResultType.StartsWith("sts-", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Reads the TLS reports that have been arriving and had nowhere to be read.
/// </summary>
/// <remarks>
/// <para>
/// The importer has parsed and stored TLS reports since it was written, the
/// schema has carried them just as long, and no page in the product ever
/// referenced them. On a real estate the records are published and pointed at
/// the operator's own mailbox - so the reports have been arriving, being
/// filed, and being invisible.
/// </para>
/// <para>
/// What they answer that DMARC cannot: DMARC says whether a message was
/// authentically from the domain. TLS reporting says whether it crossed the
/// internet encrypted. A domain can be at p=reject with perfect alignment and
/// still hand every message to a receiver in plaintext.
/// </para>
/// </remarks>
public sealed class TlsReportService(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    /// <param name="tenantId">One organization's domains, or null for every organization's.</param>
    /// <param name="clientSlug">One client's, for a customer's own login, or null.</param>
    public async Task<IReadOnlyList<TlsDomainSummary>> GetDomainsAsync(
        int days = 30, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        var since = Since(days);
        var client = Normalise(clientSlug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        command.CommandText = """
            SELECT
              d.name, c.name, c.slug,
              SUM(r.total_success),
              SUM(r.total_failure),
              COUNT(DISTINCT r.org_name),
              MAX(r.date_end),
              -- The strongest mode anybody reported. A domain reported once
              -- as enforce and once as testing in the same window is
              -- enforcing: the testing reporter simply had a stale copy.
              MAX(CASE r.policy_mode
                    WHEN 'enforce' THEN 3 WHEN 'testing' THEN 2 WHEN 'none' THEN 1 ELSE 0 END)
            FROM tls_reports r
            JOIN domains d ON d.id = r.domain_id
            JOIN clients c ON c.id = r.client_id
            WHERE r.date_end >= $since
              AND ($tenant IS NULL OR r.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
            GROUP BY d.id
            ORDER BY SUM(r.total_failure) DESC, d.name
            """;
        Bind(command, since, tenantId, client);

        var results = new List<TlsDomainSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new TlsDomainSummary
            {
                Domain = reader.GetString(0),
                ClientName = reader.GetString(1),
                ClientSlug = reader.GetString(2),
                Successful = reader.IsDBNull(3) ? 0 : reader.GetInt64(3),
                Failed = reader.IsDBNull(4) ? 0 : reader.GetInt64(4),
                Reporters = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
                LastReport = ParseDate(reader.IsDBNull(6) ? null : reader.GetString(6)),
                PolicyMode = (reader.IsDBNull(7) ? 0 : reader.GetInt32(7)) switch
                {
                    3 => "enforce",
                    2 => "testing",
                    1 => "none",
                    _ => "unknown",
                },
            });
        }

        return results;
    }

    /// <summary>Why sessions failed, worst first.</summary>
    public async Task<IReadOnlyList<TlsFailure>> GetFailuresAsync(
        int days = 30, string? tenantId = null, string? clientSlug = null, int limit = 200,
        CancellationToken ct = default)
    {
        var since = Since(days);
        var client = Normalise(clientSlug);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        command.CommandText = """
            SELECT
              d.name,
              COALESCE(NULLIF(f.result_type, ''), 'unknown'),
              COALESCE(NULLIF(f.receiving_mx_hostname, ''), ''),
              SUM(f.failed_session_count),
              MAX(r.date_end)
            FROM tls_failure_details f
            JOIN tls_reports r ON r.id = f.tls_report_id
            JOIN domains d ON d.id = r.domain_id
            JOIN clients c ON c.id = r.client_id
            WHERE r.date_end >= $since
              AND ($tenant IS NULL OR r.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
            GROUP BY d.id, f.result_type, f.receiving_mx_hostname
            ORDER BY SUM(f.failed_session_count) DESC
            LIMIT $limit
            """;
        Bind(command, since, tenantId, client);
        command.Parameters.AddWithValue("$limit", limit);

        var results = new List<TlsFailure>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            results.Add(new TlsFailure
            {
                Domain = reader.GetString(0),
                ResultType = reader.GetString(1),
                ReceivingMx = reader.GetString(2),
                Sessions = reader.IsDBNull(3) ? 0 : reader.GetInt64(3),
                LastSeen = ParseDate(reader.IsDBNull(4) ? null : reader.GetString(4)),
            });
        }

        return results;
    }

    private static void Bind(SqliteCommand command, string since, string? tenantId, string? client)
    {
        command.Parameters.AddWithValue("$since", since);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)client ?? DBNull.Value);
    }

    private static string Since(int days) =>
        DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static string? Normalise(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();

    private static DateTimeOffset? ParseDate(string? value) =>
        value is not null && DateTime.TryParse(
            value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? new DateTimeOffset(parsed, TimeSpan.Zero)
            : null;
}
