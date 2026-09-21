using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// What each domain publishes, as last read, and the one control that reads
/// it again.
///
/// The reading itself is the scheduled job's work - deploy/dmarc-dns.timer
/// runs <c>dmarc check --all --save</c> nightly - and every page here renders
/// from what that stored. Resolving on render would be eighty DNS lookups per
/// page load, each able to hang for five seconds.
///
/// The refresh is the deliberate exception, and a small one. A fresh install
/// has no readings at all until the timer first fires, so without a button
/// the whole feature is blank on the day somebody sets it up and there is
/// nothing on screen to say why. It is an operator action, gated like the
/// rest, and it is bounded: one organization, or one client inside it, never
/// the whole install.
/// </summary>
public sealed class DnsStatusService(DatabaseInfo database, AuditLog audit)
{
    private readonly DnsSnapshotStore _snapshots = new(database.Path);
    private readonly string _databasePath = database.Path;

    /// <summary>
    /// How many domains one refresh will read, whatever was asked for.
    /// </summary>
    /// <remarks>
    /// A circuit holds the page open while this runs, and each domain is an
    /// apex lookup plus one per DKIM selector - a few seconds on a slow
    /// resolver. Past this the honest answer is that it belongs to the timer,
    /// and the page says so rather than spinning for four minutes.
    /// </remarks>
    public const int RefreshLimit = 25;

    /// <param name="tenantId">One organization's domains, or null for every organization's.</param>
    /// <param name="clientSlug">One client's domains, or null for every client's.</param>
    public async Task<IReadOnlyDictionary<string, DomainDns>> GetAsync(
        string? tenantId, string? clientSlug = null, CancellationToken ct = default)
    {
        if (!File.Exists(_databasePath))
        {
            return new Dictionary<string, DomainDns>(StringComparer.OrdinalIgnoreCase);
        }

        return await _snapshots.LatestAsync(tenantId, clientSlug, DnsScanner.SelectorWindowDays, ct)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the DNS of the domains in scope again and stores what it finds.
    /// </summary>
    /// <returns>What the run did, or null when there was nothing in scope to read.</returns>
    public async Task<ScanSummary?> RefreshAsync(
        string? tenantId, string? clientSlug, string actor, CancellationToken ct = default)
    {
        if (!File.Exists(_databasePath)) { return null; }

        var scanner = new DnsScanner(_databasePath);
        var summary = await scanner
            .RunAsync(tenantId, clientSlug, domain: null, progress: null, limit: RefreshLimit, ct: ct)
            .ConfigureAwait(false);

        // Worth a line in the log: it is a write, it reaches outside the
        // machine, and a burst of them against somebody's resolver should be
        // attributable to whoever kept pressing the button.
        await audit.RecordAsync(
            tenantId, actor, "dns.refresh",
            $"{summary.Results.Count} domain(s): {summary.Read} read, {summary.Failed} failed, "
            + $"{summary.Missing} nonexistent, {summary.Changed} changed",
            ct).ConfigureAwait(false);

        return summary;
    }
}
