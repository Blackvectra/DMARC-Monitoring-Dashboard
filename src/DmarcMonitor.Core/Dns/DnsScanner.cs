using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>What reading one domain's DNS produced.</summary>
/// <param name="Domain">The domain read.</param>
/// <param name="Status">How the attempt went.</param>
/// <param name="Stored">
/// False when the domain is not in the book, so there was nothing to attach
/// the reading to. A scan over the book never sees this; a check aimed at a
/// prospect's domain does.
/// </param>
/// <param name="Changed">True when the records differ from the last stored reading.</param>
/// <param name="Selectors">How many DKIM selectors were looked up.</param>
public sealed record ScanResult(
    string Domain, DnsCheckStatus Status, bool Stored, bool Changed, int Selectors)
{
    /// <summary>What changed, record by record, when <see cref="Changed"/> is true.</summary>
    public IReadOnlyList<DriftChange> Drift { get; init; } = [];
}

/// <summary>What a whole run produced.</summary>
/// <param name="Results">One entry per domain read.</param>
/// <param name="Skipped">
/// Domains in scope that a limit stopped this run reaching. Reported rather
/// than dropped: a refresh that silently covered a third of the book would
/// leave the rest looking checked when it was not.
/// </param>
public sealed record ScanSummary(IReadOnlyList<ScanResult> Results, int Skipped = 0)
{
    public int Read => Results.Count(r => r.Status == DnsCheckStatus.Ok);
    public int Stored => Results.Count(r => r.Stored);
    public int NotInBook => Results.Count(r => !r.Stored);
    public int Failed => Results.Count(r => r.Status == DnsCheckStatus.Failed);
    public int Missing => Results.Count(r => r.Status == DnsCheckStatus.NoSuchDomain);
    public int Changed => Results.Count(r => r.Changed);
}

/// <summary>
/// Reads the DNS of every domain in the book and stores what it finds.
///
/// This is the job that makes a record indicator possible. Resolving on
/// render is fine for the one domain on a detail page and impossible for a
/// table: eighty domains is eighty lookups, each able to hang for five
/// seconds, on a page somebody reloads. So the readings are taken here, on a
/// schedule, and every screen reads storage.
///
/// Sequential rather than parallel, deliberately. The work is a few hundred
/// UDP queries against a resolver that caches, so it finishes in seconds
/// either way, and a book of clients fanning out at once is how an MSP's own
/// resolver starts rate-limiting it - which would arrive as a page full of
/// failures and read as every customer's DNS breaking at the same moment.
/// </summary>
public sealed class DnsScanner(string databasePath, DnsLookup? lookup = null, MtaStsFetcher? mtaSts = null)
{
    private readonly string _databasePath = NotBlank(databasePath);
    private readonly DnsLookup _lookup = lookup ?? new DnsLookup();
    private readonly DnsSnapshotStore _store = new(NotBlank(databasePath));

    /// <summary>
    /// Fetches the policy file a domain is serving, for the one thing about
    /// MTA-STS that DNS cannot answer.
    /// </summary>
    /// <remarks>
    /// The TXT record announces a policy id; the mode - the part that decides
    /// whether anything is required of senders - is in a file served over
    /// HTTPS. Without this a scan can store that a domain announces a policy
    /// and cannot store whether that policy enforces anything, which is the
    /// difference between protected and a domain in testing that has been
    /// producing clean reports for two years while protecting nothing.
    ///
    /// Passed in where a caller has one already, so a long-lived process
    /// reuses its connections rather than opening a pool per refresh.
    /// </remarks>
    private readonly MtaStsFetcher _mtaSts = mtaSts ?? new MtaStsFetcher();

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>
    /// How far back a report must have shown a selector signing for it to be
    /// worth looking up.
    /// </summary>
    /// <remarks>
    /// Matches the window the indicator reads back over. A selector retired
    /// last spring should stop being checked and stop being drawn, and its
    /// row is never deleted, so the window is what retires it.
    /// </remarks>
    public const int SelectorWindowDays = 30;

    /// <param name="tenantId">One organization's domains, or null for every organization's.</param>
    /// <param name="clientSlug">One client's domains, or null for every client's.</param>
    /// <param name="domain">One domain, or null for all of them in scope.</param>
    /// <param name="progress">Called after each domain, for a command that prints as it goes.</param>
    /// <param name="limit">
    /// At most this many domains, for a caller that cannot wait for the whole
    /// book - a page holding a circuit open, rather than a scheduled run. The
    /// rest are counted into the summary so nobody is told they were read.
    /// </param>
    public async Task<ScanSummary> RunAsync(
        string? tenantId = null, string? clientSlug = null, string? domain = null,
        IProgress<ScanResult>? progress = null, int? limit = null, CancellationToken ct = default)
    {
        var targets = await TargetsAsync(tenantId, clientSlug, domain, ct).ConfigureAwait(false);

        var skipped = 0;
        if (limit is { } cap && targets.Count > cap)
        {
            skipped = targets.Count - cap;
            targets = [.. targets.Take(cap)];
        }

        var results = new List<ScanResult>(targets.Count);

        foreach (var name in targets)
        {
            ct.ThrowIfCancellationRequested();

            var published = await _lookup.ReadAsync(name, ct).ConfigureAwait(false);

            // The policy a sender would really get. Only for a domain that
            // announces one: fetching for the rest would be an HTTPS request
            // per domain to a host nobody has claimed exists.
            if (!string.IsNullOrWhiteSpace(published.MtaStsRecord))
            {
                published = published with
                {
                    ServedMtaSts = await _mtaSts.FetchAsync(name, ct: ct).ConfigureAwait(false),
                };
            }

            var result = await SaveAsync(name, published, tenantId, ct).ConfigureAwait(false);

            results.Add(result);
            progress?.Report(result);
        }

        return new ScanSummary(results, skipped);
    }

    /// <summary>
    /// Stores a reading somebody else has already taken, looking up that
    /// domain's DKIM selectors to go with it.
    /// </summary>
    /// <remarks>
    /// Exists so <c>dmarc check --save</c> does not resolve the apex twice.
    /// That command reads the records to judge them, and judging and storing
    /// should not disagree about what was published - which they could, a
    /// second apart, on a record somebody is editing.
    /// </remarks>
    /// <param name="tenantId">
    /// The organization whose domain this is, or null for every one. A domain
    /// name is unique per organization and not globally, so a reading saved
    /// without it can land on another organization's row of the same name, and
    /// the selectors read from the reports can be another organization's too.
    /// </param>
    public async Task<ScanResult> SaveAsync(
        string domain, PublishedRecords published, string? tenantId = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentNullException.ThrowIfNull(published);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var readings = new List<SelectorReading>();

        // Selectors are only worth asking about when the apex answered.
        // Querying them for a domain whose own lookup just failed spends time
        // learning the same thing again, and for a name that does not exist it
        // asks about keys in a zone nobody owns.
        if (!published.LookupFailed && !published.DomainDoesNotExist)
        {
            foreach (var (selector, lastSeen) in await SelectorsSeenSigningAsync(name, tenantId, ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();
                var key = await _lookup.DkimAsync(name, selector, ct).ConfigureAwait(false);
                readings.Add(new SelectorReading(selector, key, lastSeen));
            }
        }

        var save = await _store.SaveAsync(name, published, readings, tenantId, ct).ConfigureAwait(false);

        var status = published switch
        {
            { LookupFailed: true } => DnsCheckStatus.Failed,
            { DomainDoesNotExist: true } => DnsCheckStatus.NoSuchDomain,
            _ => DnsCheckStatus.Ok,
        };

        return new ScanResult(name, status, save.Stored, save.Changed, readings.Count) { Drift = save.Drift };
    }

    private async Task<List<string>> TargetsAsync(
        string? tenantId, string? clientSlug, string? domain, CancellationToken ct)
    {
        var names = new List<string>();

        await using var db = new SqliteConnection(ReadOnly());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.name
            FROM domains d
            JOIN clients c ON c.id = d.client_id
            WHERE d.is_active = 1 AND d.deleted_at IS NULL
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
              AND ($client IS NULL OR c.slug = $client)
              AND ($domain IS NULL OR d.name = $domain)
            ORDER BY d.name
            """;
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$client", (object?)Lower(clientSlug) ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)Lower(domain) ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add(reader.GetString(0)); }

        return names;
    }

    /// <summary>
    /// Every selector the reports have shown signing for each domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Filtered to signatures that actually verified and that were made for
    /// this domain or a subdomain of it. Both halves are needed. Anyone can
    /// sign a message claiming to be somebody else's domain, and the reports
    /// faithfully record the attempt: taking every selector that appears
    /// would have this look up a spoofer's selector under the victim's name,
    /// find nothing, and report the victim's DKIM as broken. A signature that
    /// verified against a key at that name is proof the key was there, which
    /// is the only proof available.
    /// </para>
    /// <para>
    /// The window matters as much. dkim_selectors rows are never deleted, so
    /// without it a selector retired two years ago would be looked up forever
    /// and drawn as a broken key forever.
    /// </para>
    /// </remarks>
    /// <param name="tenantId">
    /// One organization's copy of this domain, or null for every one. Two
    /// organizations on one install may each hold a domain of the same name,
    /// and merging their reports would show one of them the other's selectors.
    /// </param>
    public async Task<IReadOnlyList<(string Selector, DateTimeOffset LastSeen)>> SelectorsSeenSigningAsync(
        string domain, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var found = new List<(string, DateTimeOffset)>();

        await using var db = new SqliteConnection(ReadOnly());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT r.dkim_selector, MAX(r.date_begin)
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE LOWER(d.name) = $domain
              AND d.is_active = 1 AND d.deleted_at IS NULL
              AND r.dkim_selector IS NOT NULL AND TRIM(r.dkim_selector) <> ''
              AND r.dkim_auth_result = 'pass'
              AND r.dkim_domain IS NOT NULL
              AND (LOWER(r.dkim_domain) = LOWER(d.name)
                OR LOWER(r.dkim_domain) LIKE '%.' || LOWER(d.name))
              AND r.date_begin >= $since
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
            GROUP BY r.dkim_selector
            ORDER BY r.dkim_selector
            """;
        command.Parameters.AddWithValue("$domain", domain);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$since", DateTimeOffset.UtcNow.AddDays(-SelectorWindowDays)
            .UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var lastSeen = DateTime.TryParse(reader.GetString(1), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
                ? new DateTimeOffset(parsed, TimeSpan.Zero)
                : DateTimeOffset.UtcNow;

            found.Add((reader.GetString(0).Trim(), lastSeen));
        }

        return found;
    }

    private string ReadOnly() => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();

    private static string? Lower(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();
}
