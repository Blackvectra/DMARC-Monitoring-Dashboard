using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Intelligence;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// Which of the sources on a page still have no name, and the one control that
/// looks them up now.
///
/// Naming is the nightly job's work - <c>dmarc intel --names</c>, run by the
/// timer on a server install - and every page renders from what that stored,
/// because a page that resolved as it rendered would make one DNS query per
/// row against addresses chosen by whoever mailed the reports.
///
/// The button is the same deliberate exception the Domains page makes for
/// reading DNS, for the same reason: a Windows trial has no scheduler, so
/// without it the table is a column of bare addresses for ever and nothing on
/// the page says why. It is an operator action, it is bounded, and it names
/// the addresses the person is looking at rather than the estate's busiest.
/// </summary>
public sealed class SourceNamingService(DatabaseInfo database, AuditLog audit, DnsLookup dns)
{
    private readonly SourceNameStore _store = new(database.Path);
    private readonly SourceNameResolver _resolver = new(new SourceNameStore(database.Path), dns);

    /// <summary>
    /// How many addresses one press looks up, whatever was asked for.
    /// </summary>
    /// <remarks>
    /// A circuit holds the page open while this runs. Each address is a
    /// reverse lookup and a forward check, eight at a time, and a dead reverse
    /// zone costs a timeout - so forty is a handful of seconds on a good day
    /// and well under a minute on a bad one. Past this the honest answer is
    /// that it belongs to the nightly job, and the page says so rather than
    /// spinning.
    /// </remarks>
    public const int LookupLimit = 40;

    /// <summary>
    /// How many of these addresses are due a lookup: never asked about, asked
    /// long enough ago to ask again, or named but never checked against their
    /// own forward records.
    /// </summary>
    /// <param name="addresses">
    /// Addresses the page has already read from reports in the caller's own
    /// scope. Only the names table is consulted, so asking costs the same for
    /// a customer's login as for a master's and opens nobody's reports.
    /// </param>
    public async Task<int> DueAsync(IReadOnlyCollection<string> addresses, CancellationToken ct = default)
    {
        if (addresses.Count == 0 || !File.Exists(database.Path)) { return 0; }

        return (await _store.DueAmongAsync(addresses, ct: ct).ConfigureAwait(false)).Count;
    }

    /// <summary>
    /// Looks up the first of these addresses that are due, in the order given.
    /// </summary>
    /// <param name="tenantId">The organization the addresses belong to, for the audit entry.</param>
    /// <param name="addresses">
    /// Read from reports in the caller's own scope, busiest first: a press
    /// names as many as it can, and the ones somebody is looking at hardest
    /// should be among them.
    /// </param>
    /// <returns>What the run did, or null when there is no database to store a name in.</returns>
    public async Task<SourceNameRun?> LookUpAsync(
        string? tenantId, string actor, IReadOnlyCollection<string> addresses, CancellationToken ct = default)
    {
        if (!File.Exists(database.Path)) { return null; }

        var run = await _resolver.RunAsync(addresses, LookupLimit, ct).ConfigureAwait(false);

        // Worth a line in the log: it reaches outside the machine, and a burst
        // of lookups against somebody's resolver should be attributable to
        // whoever kept pressing the button.
        await audit.RecordAsync(
            tenantId, actor, "sources.names",
            $"{run.Looked} address(es): {run.Named} named, {run.Confirmed} confirmed by their own forward records",
            ct).ConfigureAwait(false);

        return run;
    }
}
