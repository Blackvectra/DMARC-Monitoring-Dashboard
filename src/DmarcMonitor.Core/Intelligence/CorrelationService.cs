using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Intelligence;

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

    /// <summary>
    /// How many of the domains it fails against it has also passed for.
    /// </summary>
    public int DomainsAlsoPassed { get; init; }

    /// <summary>
    /// A real sending path for every domain it touches.
    /// </summary>
    /// <remarks>
    /// Passing is the thing a forger cannot do, since it does not hold the
    /// signing key - but only for the domain it passed FOR. Requiring every
    /// domain keeps an address that genuinely carries one client from being
    /// cleared of forging the rest, which is what a fleet-wide test did.
    /// </remarks>
    public bool IsOwnSendingPath => DomainCount > 0 && DomainsAlsoPassed >= DomainCount;

    public int DomainCount => Domains.Count;
    public int ClientCount => Clients.Count;

    /// <summary>
    /// How many unrelated parties this source was seen against.
    /// </summary>
    /// <remarks>
    /// Clients, except that every domain still sitting in the Unassigned
    /// bucket counts for itself. Unassigned is a waiting room, not a customer:
    /// two domains in it are no more related than two domains belonging to
    /// different clients, and counting the bucket as one client meant a fresh
    /// install - where everything is unassigned - could never see a source
    /// working through several of them.
    /// </remarks>
    public int IndependentParties { get; init; }

    /// <summary>Seen against more than one unrelated party. Only a multi-client platform can see this.</summary>
    public bool IsCrossClient => IndependentParties > 1;

    /// <summary>
    /// What the address reverses to, or null when nothing has looked yet.
    /// </summary>
    public string? ReverseName { get; init; }

    /// <summary>
    /// The source as it should be written down: the vendor if the catalogue
    /// recognises one, else the reverse name, else the address.
    /// </summary>
    /// <remarks>
    /// Never empty and never a guess. An address nobody can name prints as an
    /// address, which is what every row was before any of this existed - so
    /// the worst case here is the old best case.
    ///
    /// The name is for reading, never for judging. A PTR is written by
    /// whoever holds the address, so recognising "ColoCrossing" says who owns
    /// the wire and nothing about whether the mail is legitimate. Every
    /// verdict on this record still comes from what was signed and from how
    /// many unrelated parties the address was seen against.
    /// </remarks>
    public string Display =>
        SourceCatalog.Identify(ReverseName) is { } known ? known.Name
        : !string.IsNullOrWhiteSpace(ReverseName) ? ReverseName
        : SourceIp;

    /// <summary>Whether anything better than the address is known.</summary>
    public bool IsNamed => Display != SourceIp;

    public bool AuthenticatedNothing => AuthenticatedFor.Count == 0;

    /// <summary>
    /// What this most likely is. Deliberately cautious: calling a customer's
    /// own marketing platform an attacker is how an operator blocks their
    /// client's invoices.
    /// </summary>
    public SourceVerdict Verdict =>
        // Being a real sending path outranks what any individual failing row
        // looks like. Judging on the failing rows alone put a customer's own
        // relay under cross-client impersonation against seven of their
        // clients.
        IsOwnSendingPath || !AuthenticatedNothing ? SourceVerdict.Misconfigured
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
public sealed class CorrelationService(string databasePath)
{
    // Opens its own read-only connection, like the other services in Core.
    // Living here rather than beside the page is the point: this classifies a
    // sending source, which is the same judgment the client report and the
    // intelligence make, and the three disagreeing about one address is how
    // the worst bug of the day was found. A rule this load-bearing belongs
    // where it can be tested.
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    /// <param name="tenantId">
    /// One organization's clients, or null for every organization's. Scoped
    /// even though the whole point of this page is seeing across clients:
    /// across NRG's clients is the product; across NRG's and NextLayerSec's
    /// is a leak.
    /// </param>
    /// <param name="clientSlug">One client's domains only, for a customer's own login, or null.</param>
    public async Task<IReadOnlyList<FailingSource>> GetFailingSourcesAsync(
        int days = 30, int limit = 200, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();

        // Overrides are excluded. A mailing list or forwarder breaking
        // authentication is expected behavior, and including it would bury
        // the real findings under traffic nobody should act on.
        command.CommandText = """
            SELECT
              r.source_ip,
              SUM(r.message_count)                                   AS failed,
              GROUP_CONCAT(DISTINCT d.name)                          AS domains,
              GROUP_CONCAT(DISTINCT c.name)                          AS clients,
              -- Independent parties, not rows in the clients table. A domain
              -- nobody has filed yet sits in the single "Unassigned" bucket
              -- with every other unfiled domain, so counting clients made
              -- every source on a fresh install look like it touched exactly
              -- one - and cross-client impersonation, the one thing only a
              -- multi-client platform can see, could never fire until an
              -- operator had finished onboarding. Unfiled domains are not
              -- related to each other; each counts for itself.
              COUNT(DISTINCT CASE WHEN c.slug = 'unassigned' THEN d.name ELSE c.id END) AS parties,
              MAX(r.date_begin)                                      AS last_seen,
              GROUP_CONCAT(DISTINCT
                CASE WHEN r.spf_auth_result = 'pass' THEN COALESCE(r.spf_domain, '') ELSE '' END
                || '|' ||
                CASE WHEN r.dkim_auth_result = 'pass' THEN COALESCE(r.dkim_domain, '') ELSE '' END) AS auth,
              -- How many of the domains this address is failing against it
              -- has ALSO passed for. Per domain, not fleet-wide: 3.231.237.226
              -- passed twice for one client and signs as three others it has
              -- never passed for, and a fleet-wide test cleared it entirely.
              -- Only the failing rows are selected above, so without this the
              -- query cannot tell a customer's own gateway - which signs for
              -- them and breaks a share of its signatures in transit - from
              -- somebody sending as them.
              (SELECT COUNT(DISTINCT f.domain_id)
                 FROM aggregate_records f
                WHERE f.source_ip = r.source_ip
                  AND f.dmarc_result = 'fail'
                  AND EXISTS (SELECT 1 FROM aggregate_records p
                               WHERE p.source_ip = f.source_ip
                                 AND p.domain_id = f.domain_id
                                 AND p.dmarc_result = 'pass')) AS domains_also_passed,
              -- What the address reverses to, if anything has looked. Joined
              -- rather than resolved per row: a page cannot make a DNS query
              -- while it renders, least of all one per row against addresses
              -- chosen by whoever mailed the reports. Absent is ordinary and
              -- means the nightly pass has not reached it yet, in which case
              -- the address is printed exactly as it always was.
              n.reverse_name                                        AS reverse_name
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            JOIN clients c ON c.id = r.client_id
            LEFT JOIN source_names n ON n.ip = r.source_ip
            WHERE r.dmarc_result = 'fail'
              AND r.date_begin >= $since
              AND (r.override_reason IS NULL OR r.override_reason = '')
              AND ($tenant IS NULL OR r.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
            GROUP BY r.source_ip
            ORDER BY COUNT(DISTINCT CASE WHEN c.slug = 'unassigned' THEN d.name ELSE c.id END) DESC, failed DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$since", since);
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)(string.IsNullOrWhiteSpace(clientSlug) ? null : clientSlug.Trim().ToLowerInvariant()) ?? DBNull.Value);

        var results = new List<FailingSource>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);

        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var domains = Split(reader.IsDBNull(2) ? "" : reader.GetString(2));
            var clients = Split(reader.IsDBNull(3) ? "" : reader.GetString(3));

            DateTimeOffset? lastSeen = null;
            if (!reader.IsDBNull(5) &&
                DateTime.TryParse(reader.GetString(5), CultureInfo.InvariantCulture,
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
                IndependentParties = reader.IsDBNull(4) ? clients.Count : reader.GetInt32(4),
                LastSeen = lastSeen,
                AuthenticatedFor = ParseAuthDomains(reader.IsDBNull(6) ? "" : reader.GetString(6)),
                DomainsAlsoPassed = reader.IsDBNull(7) ? 0 : reader.GetInt32(7),
                ReverseName = reader.IsDBNull(8) ? null : reader.GetString(8),
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

    /// <summary>
    /// Everything one source has done, across every domain in scope.
    /// </summary>
    /// <remarks>
    /// The page behind a source's name. Asked about one address, a domain
    /// owner's dashboard can only say what it did to them; this says it did
    /// the same to six unrelated businesses on the same afternoon, which is
    /// the finding worth paying for.
    ///
    /// All traffic, not only the failing rows. A source that authenticates
    /// properly nine times in ten and fails on the tenth is the commonest
    /// real case, and a page that showed only the tenth would describe a
    /// working mail path as a threat.
    /// </remarks>
    /// <param name="tenantId">One organization's clients, or null for all. Scoped for the same reason the list is.</param>
    /// <param name="clientSlug">One client's domains, for a customer's own login, or null.</param>
    public async Task<SourceDetail?> GetSourceAsync(
        string sourceIp, int days = 30, string? tenantId = null, string? clientSlug = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceIp);

        var ip = sourceIp.Trim();
        var since = DateTimeOffset.UtcNow.AddDays(-days).UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        var client = string.IsNullOrWhiteSpace(clientSlug) ? null : clientSlug.Trim().ToLowerInvariant();

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var appearances = new List<SourceAppearance>();

        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT
                  d.name, c.name, c.slug,
                  SUM(r.message_count),
                  SUM(CASE WHEN r.dmarc_result = 'pass' THEN r.message_count ELSE 0 END),
                  MAX(r.date_begin),
                  -- Ever passed FOR THIS DOMAIN. Per domain because passing is
                  -- the thing a forger cannot do, and only for the domain it
                  -- passed for: an address carrying one customer's mail
                  -- properly is not thereby cleared of forging the rest.
                  MAX(CASE WHEN r.dmarc_result = 'pass' THEN 1 ELSE 0 END)
                FROM aggregate_records r
                JOIN domains d ON d.id = r.domain_id
                JOIN clients c ON c.id = r.client_id
                WHERE r.source_ip = $ip
                  AND r.date_begin >= $since
                  AND ($tenant IS NULL OR r.tenant_id = $tenant)
                  AND ($client IS NULL OR c.slug = $client)
                GROUP BY d.id
                ORDER BY SUM(r.message_count) DESC
                """;
            command.Parameters.AddWithValue("$ip", ip);
            command.Parameters.AddWithValue("$since", since);
            command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
            command.Parameters.AddWithValue("$client", (object?)client ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                DateTimeOffset? last = null;
                if (!reader.IsDBNull(5) && DateTime.TryParse(
                        reader.GetString(5), CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
                {
                    last = new DateTimeOffset(parsed, TimeSpan.Zero);
                }

                appearances.Add(new SourceAppearance
                {
                    Domain = reader.GetString(0),
                    ClientName = reader.GetString(1),
                    ClientSlug = reader.GetString(2),
                    Messages = reader.IsDBNull(3) ? 0 : reader.GetInt64(3),
                    Passing = reader.IsDBNull(4) ? 0 : reader.GetInt64(4),
                    LastSeen = last,
                    EverPassed = !reader.IsDBNull(6) && reader.GetInt32(6) == 1,
                });
            }
        }

        // An address nobody has a report for in this window is not found,
        // rather than an empty page about an address that may not exist.
        if (appearances.Count == 0) { return null; }

        string auth;
        string? reverseName;

        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT
                  COALESCE(GROUP_CONCAT(DISTINCT
                    CASE WHEN r.spf_auth_result = 'pass' THEN COALESCE(r.spf_domain, '') ELSE '' END
                    || '|' ||
                    CASE WHEN r.dkim_auth_result = 'pass' THEN COALESCE(r.dkim_domain, '') ELSE '' END), ''),
                  (SELECT n.reverse_name FROM source_names n WHERE n.ip = $ip)
                FROM aggregate_records r
                JOIN clients c ON c.id = r.client_id
                WHERE r.source_ip = $ip
                  AND r.date_begin >= $since
                  AND r.dmarc_result = 'fail'
                  AND ($tenant IS NULL OR r.tenant_id = $tenant)
                  AND ($client IS NULL OR c.slug = $client)
                """;
            command.Parameters.AddWithValue("$ip", ip);
            command.Parameters.AddWithValue("$since", since);
            command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
            command.Parameters.AddWithValue("$client", (object?)client ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            var read = await reader.ReadAsync(ct).ConfigureAwait(false);
            auth = read && !reader.IsDBNull(0) ? reader.GetString(0) : "";
            reverseName = read && !reader.IsDBNull(1) ? reader.GetString(1) : null;
        }

        return new SourceDetail
        {
            SourceIp = ip,
            ReverseName = reverseName,
            Appearances = appearances,
            AuthenticatedFor = ParseAuthDomains(auth),
        };
    }
}

/// <summary>One domain a source has been seen sending as.</summary>
public sealed record SourceAppearance
{
    public required string Domain { get; init; }
    public required string ClientName { get; init; }
    public required string ClientSlug { get; init; }
    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing => Messages - Passing;
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>Whether this source has ever authenticated for this domain.</summary>
    /// <remarks>
    /// Per domain, and that is the whole value of the column. Passing is the
    /// thing a forger cannot do - but only for the domain it passed for. A
    /// source that carries one customer's mail properly and sends as three
    /// others it has never passed for is not vindicated by the first.
    /// </remarks>
    public bool EverPassed { get; init; }
}

/// <summary>
/// Everything one sending source has done across the whole estate.
/// </summary>
/// <remarks>
/// The view a single-tenant tool cannot produce. Asked about 192.3.180.38, a
/// domain owner's dashboard can say what it did to them; only something
/// holding several customers' reports can say it did the same to six others
/// on the same afternoon.
/// </remarks>
public sealed record SourceDetail
{
    public required string SourceIp { get; init; }
    public string? ReverseName { get; init; }
    public IReadOnlyList<SourceAppearance> Appearances { get; init; } = [];

    /// <summary>Domains this source authenticated FOR, when it failed.</summary>
    public IReadOnlyList<string> AuthenticatedFor { get; init; } = [];

    public long Messages => Appearances.Sum(a => a.Messages);
    public long Passing => Appearances.Sum(a => a.Passing);
    public long Failing => Appearances.Sum(a => a.Failing);

    public DateTimeOffset? LastSeen =>
        Appearances.Where(a => a.LastSeen is not null).Max(a => a.LastSeen);

    public int DomainCount => Appearances.Count;

    /// <summary>
    /// Unrelated parties, counting each unfiled domain for itself.
    /// </summary>
    /// <remarks>
    /// Every imported domain starts in the single Unassigned bucket, so
    /// counting clients made every source on a fresh install look like it
    /// touched exactly one. Two domains nobody has filed yet are no more
    /// related than two belonging to different customers.
    /// </remarks>
    public int IndependentParties => Appearances
        .Select(a => a.ClientSlug.Equals("unassigned", StringComparison.OrdinalIgnoreCase)
            ? $"domain:{a.Domain}" : $"client:{a.ClientSlug}")
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Count();

    public bool IsCrossClient => IndependentParties > 1;

    /// <summary>A real sending path for every domain it touches.</summary>
    public bool IsOwnSendingPath => DomainCount > 0 && Appearances.All(a => a.EverPassed);

    public bool AuthenticatedNothing => AuthenticatedFor.Count == 0;

    /// <summary>The same judgement the list makes, from the same inputs.</summary>
    /// <remarks>
    /// Deliberately identical to <see cref="FailingSource.Verdict"/>. Two
    /// screens disagreeing about one address is worse than either being
    /// wrong, because an operator cannot tell which to believe.
    /// </remarks>
    public SourceVerdict Verdict =>
        IsOwnSendingPath || !AuthenticatedNothing ? SourceVerdict.Misconfigured
        : IsCrossClient ? SourceVerdict.CrossClientImpersonation
        : SourceVerdict.Unauthenticated;

    /// <summary>The vendor the catalogue recognises, else the reverse name, else the address.</summary>
    public string Display =>
        SourceCatalog.Identify(ReverseName) is { } known ? known.Name
        : !string.IsNullOrWhiteSpace(ReverseName) ? ReverseName
        : SourceIp;

    public bool IsNamed => Display != SourceIp;

    /// <summary>What kind of sender this is, when the catalogue knows.</summary>
    public SourceKind Kind =>
        SourceCatalog.Identify(ReverseName) is { } known ? known.Kind : SourceKind.Unknown;
}
