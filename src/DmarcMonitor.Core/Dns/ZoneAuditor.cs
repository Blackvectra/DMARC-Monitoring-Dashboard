using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>What auditing one zone file produced.</summary>
/// <param name="Zone">What was read out of the file.</param>
/// <param name="Evidence">What was learned from outside it.</param>
/// <param name="Findings">What is wrong, worst first.</param>
/// <param name="SelectorsNotChecked">
/// Selectors a limit stopped this run resolving. Counted rather than dropped:
/// an audit that quietly checked a third of a zone's keys would leave the rest
/// looking clean.
/// </param>
/// <param name="Offline">True when neither DNS nor the reports were consulted.</param>
public sealed record ZoneAuditReport(
    ParsedZone Zone,
    ZoneEvidence Evidence,
    IReadOnlyList<ZoneFinding> Findings,
    int SelectorsNotChecked = 0,
    bool Offline = false)
{
    public bool AnythingBreaking => Findings.Any(f => f.Severity == HygieneSeverity.Breaking);

    /// <summary>What the file turned out to hold.</summary>
    public string ReadSummary =>
        Zone.Problems.Count == 0
            ? $"{Zone.Records.Count} record(s) read from the file"
            : $"{Zone.Records.Count} record(s) read from the file; "
              + $"{Zone.Problems.Count} line(s) could not be read";

    /// <summary>
    /// What was asked, besides the file.
    /// </summary>
    /// <remarks>
    /// The sentence that decides how much the rest is worth, and the reason it
    /// is computed here rather than written out by each caller. A run that
    /// could not reach a resolver produces findings about a file and nothing
    /// else, and a screen that said "DNS: read" over one of those would be
    /// making the same claim as a tick drawn for a record nobody looked up.
    /// </remarks>
    public string EvidenceSummary
    {
        get
        {
            if (Offline)
            {
                return "judged on the file alone: neither DNS nor the reports were consulted";
            }

            var dns = Evidence.Live switch
            {
                null => "DNS: not read",
                { DomainDoesNotExist: true } => "DNS: the resolver says this name does not exist",
                { LookupFailed: true } => "DNS: could not be read, so nothing below is confirmed against it",
                _ => $"DNS: read, {Evidence.Selectors.Count} selector(s) resolved",
            };

            var reports = Evidence switch
            {
                { ReportsRead: false } or { ReportWindowDays: 0 } => "reports: none held for this domain",
                { ReportWindowDays: < ZoneAudit.MinimumDaysToJudgeASelector } e =>
                    $"reports: {e.ReportWindowDays} day(s), too few to judge a selector on silence",
                var e => $"reports: {e.ReportWindowDays} days, {e.SeenSigning.Count} selector(s) seen signing",
            };

            return $"{dns}; {reports}";
        }
    }
}

/// <summary>
/// Runs a zone file past live DNS and past the reports.
///
/// The network and the database live here so that <see cref="ZoneAudit"/> can
/// stay pure. Everything this gathers is optional: with no resolver the file
/// is still judged on what it says about itself, and with no database the
/// findings that need to know what has actually been signing simply do not
/// appear. What never happens is a finding that claims evidence this did not
/// collect.
/// </summary>
/// <param name="tenantId">
/// The organization on whose behalf this runs, or null for every one.
///
/// Not optional in spirit. A domain name is unique per organization and not
/// globally, so an audit that reads the book by name alone answers with
/// another organization's DKIM selectors, report counts and domain list. Null
/// is right for a command-line run by the operator and wrong for anything
/// serving a signed-in person.
/// </param>
public sealed class ZoneAuditor(
    DnsLookup? lookup = null, string? databasePath = null, string? tenantId = null)
{
    private readonly DnsLookup _lookup = lookup ?? new DnsLookup();
    private readonly string? _databasePath = string.IsNullOrWhiteSpace(databasePath) ? null : databasePath;
    private readonly string? _tenantId = string.IsNullOrWhiteSpace(tenantId) ? null : tenantId;

    /// <summary>
    /// How many selectors one run will resolve.
    /// </summary>
    /// <remarks>
    /// Each is a DNS query that can take seconds, and this runs behind a page
    /// as well as behind a command. A zone with more selectors than this is
    /// unusual enough that saying so is better than spending four minutes on
    /// it without a word.
    /// </remarks>
    public const int SelectorLimit = 50;

    /// <param name="text">The zone file, as pasted or read from disk.</param>
    /// <param name="domain">The apex, when the file does not say or the header was trimmed off.</param>
    /// <param name="offline">
    /// Judge the file on its own, touching neither DNS nor the database. What
    /// the file cannot establish alone is then left unsaid rather than guessed.
    /// </param>
    public async Task<ZoneAuditReport> RunAsync(
        string? text, string? domain = null, bool offline = false, CancellationToken ct = default)
    {
        var zone = ZoneFile.Parse(text, domain);

        // Before anything reaches the network. A file that names a different
        // domain is the wrong file, and running eighty DNS queries about the
        // right domain to judge the wrong one's records would produce a full
        // page of confident nonsense.
        var asked = domain?.Trim().TrimEnd('.').ToLowerInvariant();
        if (!string.IsNullOrEmpty(asked)
            && zone.DeclaredOrigin.Length > 0
            && !zone.DeclaredOrigin.Equals(asked, StringComparison.OrdinalIgnoreCase))
        {
            return new ZoneAuditReport(
                zone, new ZoneEvidence(), [ZoneAudit.WrongZone(zone.DeclaredOrigin, asked)],
                SelectorsNotChecked: 0, Offline: true);
        }

        if (offline || zone.Origin.Length == 0)
        {
            var nothing = new ZoneEvidence();
            return new ZoneAuditReport(
                zone, nothing, ZoneAudit.Assess(zone, nothing), SelectorsNotChecked: 0, Offline: offline);
        }

        var selectors = ZoneAudit.SelectorsIn(zone);
        var checkable = selectors.Count > SelectorLimit ? selectors.Take(SelectorLimit).ToList() : selectors;

        var live = await _lookup.ReadAsync(zone.Origin, ct).ConfigureAwait(false);
        var delegation = await _lookup.NsAsync(zone.Origin, ct).ConfigureAwait(false);

        var (seen, windowDays, reportsRead) = await ReportsAsync(zone.Origin, ct).ConfigureAwait(false);
        var monitored = await MonitoredAsync(ct).ConfigureAwait(false);

        var readings = new Dictionary<string, SelectorEvidence>(StringComparer.OrdinalIgnoreCase);

        // Only when the apex answered. Asking about keys in a zone whose own
        // name does not resolve spends time learning the same thing again, and
        // every answer would be an absence that proves nothing.
        if (live is { LookupFailed: false, DomainDoesNotExist: false })
        {
            foreach (var selector in checkable)
            {
                ct.ThrowIfCancellationRequested();

                var records = await _lookup.DkimRecordsAsync(zone.Origin, selector, ct).ConfigureAwait(false);

                readings[selector] = new SelectorEvidence
                {
                    Selector = selector,
                    LiveRecords = records,
                    LiveKey = records is null ? null : DkimKey.Choose(selector, records),
                    SeenSigning = seen.Contains(selector, StringComparer.OrdinalIgnoreCase),
                };
            }
        }

        var evidence = new ZoneEvidence
        {
            Live = live,
            Delegation = delegation,
            Selectors = readings,
            SeenSigning = seen,
            ReportsRead = reportsRead,
            ReportWindowDays = windowDays,
            Monitored = monitored,
        };

        return new ZoneAuditReport(
            zone, evidence, ZoneAudit.Assess(zone, evidence), selectors.Count - checkable.Count);
    }

    /// <summary>
    /// What the reports say about this domain: which selectors have signed,
    /// and over how long a run of reports.
    /// </summary>
    /// <remarks>
    /// The window is read rather than assumed. It decides whether "this
    /// selector has never signed" is a finding or a sentence about nothing,
    /// and quoting thirty days over two days of history would be inventing
    /// the evidence.
    /// </remarks>
    private async Task<(IReadOnlyList<string> Seen, int WindowDays, bool Read)> ReportsAsync(
        string domain, CancellationToken ct)
    {
        if (_databasePath is null || !File.Exists(_databasePath)) { return ([], 0, false); }

        try
        {
            var scanner = new DnsScanner(_databasePath, _lookup);
            var signing = await scanner.SelectorsSeenSigningAsync(domain, _tenantId, ct).ConfigureAwait(false);

            return ([.. signing.Select(s => s.Selector)], await WindowAsync(domain, ct).ConfigureAwait(false), true);
        }
        catch (SqliteException)
        {
            // A database that cannot be read is not a domain with no reports.
            // Everything that leans on the reports stays silent instead.
            return ([], 0, false);
        }
    }

    /// <summary>
    /// Every domain this install watches, for judging the reporting
    /// authorizations a zone publishes on other domains' behalf.
    /// </summary>
    /// <remarks>
    /// Empty when there is no database, which leaves the check silent rather
    /// than reporting every authorization as pointing at a stranger.
    /// </remarks>
    private async Task<IReadOnlyList<string>> MonitoredAsync(CancellationToken ct)
    {
        if (_databasePath is null || !File.Exists(_databasePath)) { return []; }

        try
        {
            var names = new List<string>();

            await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadOnly,
            }.ToString());

            await db.OpenAsync(ct).ConfigureAwait(false);

            await using var command = db.CreateCommand();
            command.CommandText =
                "SELECT LOWER(name) FROM domains "
                + "WHERE is_active = 1 AND deleted_at IS NULL "
                + "  AND ($tenant IS NULL OR tenant_id = $tenant)";
            command.Parameters.AddWithValue("$tenant", (object?)_tenantId ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add(reader.GetString(0)); }

            return names;
        }
        catch (SqliteException)
        {
            return [];
        }
    }

    private async Task<int> WindowAsync(string domain, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT MIN(r.date_begin), MAX(r.date_begin)
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE LOWER(d.name) = $domain AND d.is_active = 1 AND d.deleted_at IS NULL
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
            """;
        command.Parameters.AddWithValue("$domain", domain.ToLowerInvariant());
        command.Parameters.AddWithValue("$tenant", (object?)_tenantId ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0)) { return 0; }

        if (!DateTime.TryParse(reader.GetString(0), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var first)
            || !DateTime.TryParse(reader.GetString(1), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var last))
        {
            return 0;
        }

        return (int)(last - first).TotalDays + 1;
    }
}
