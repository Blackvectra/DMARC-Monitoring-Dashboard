using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Intelligence;

/// <summary>What one pass of reverse lookups did.</summary>
/// <param name="Looked">Addresses asked about.</param>
/// <param name="Named">Of those, how many came back with a name.</param>
/// <param name="Silent">
/// Of those, how many came back with none: no reverse record, or a reverse
/// zone that did not answer, which a lookup cannot tell apart.
/// </param>
/// <param name="Confirmed">Of the named, how many names point back at the address.</param>
public readonly record struct SourceNameRun(int Looked, int Named, int Silent, int Confirmed = 0)
{
    /// <summary>Of the addresses asked about, how many now have nothing to show but digits.</summary>
    public int Unnamed => Looked - Named;

    /// <summary>
    /// A whole run, of a size worth reading anything into, and not one name.
    /// </summary>
    /// <remarks>
    /// Far more often a resolver that is not answering - an offline machine, a
    /// firewall that drops DNS - than that many addresses which publish
    /// nothing. Said as such, and recorded so the addresses are asked again
    /// tomorrow and not next month.
    /// </remarks>
    public bool NothingAnswered => Looked >= SourceNameResolver.AtOnce && Named == 0;

    public string Describe() => Looked == 0
        ? "Every source already has a name; nothing to look up."
        : NothingAnswered
            ? $"Looked up {Looked} source(s) and none came back with a name. That is usually a resolver that is "
            + "not answering - check that this machine can reach a DNS server - rather than that many addresses "
            + "with no reverse record. They will be asked again tomorrow."
            : $"Looked up {Looked} source(s): {Named} named ({Confirmed} confirmed by their own forward records), "
            + $"{Unnamed} with no name.";
}

/// <summary>
/// Fills the reverse-name cache, so the pages that list sources have
/// something better than an address to print.
/// </summary>
/// <remarks>
/// <para>
/// Runs on a schedule rather than on demand. A page that resolved as it
/// rendered would make one query per row, on the request thread, against
/// addresses chosen by whoever sent the reports - which is slow when the
/// reverse zones answer and an outage when they do not.
/// </para>
/// <para>
/// Worst first: <see cref="SourceNameStore.NeedingLookupAsync"/> orders by
/// message volume, so a pass cut short by its limit has still named the
/// sources somebody is actually looking at. The long tail of addresses that
/// sent one message each can wait for tomorrow.
/// </para>
/// </remarks>
public sealed class SourceNameResolver(SourceNameStore store, DnsLookup dns)
{
    private readonly SourceNameStore _store = store;
    private readonly DnsLookup _dns = dns;

    /// <summary>
    /// How many lookups are in flight at once.
    /// </summary>
    /// <remarks>
    /// Reverse lookups are latency, not work, so serially this takes as long
    /// as the sum of every timeout - on an estate with a few hundred sources
    /// and several dead reverse zones, long enough that a nightly job would
    /// still be running at breakfast. Eight is the same figure the Fix page
    /// settled on for the same reason, and it keeps a burst of queries from
    /// looking like something a resolver should rate-limit.
    /// </remarks>
    public const int AtOnce = 8;

    public async Task<SourceNameRun> RunAsync(int limit = 500, CancellationToken ct = default)
    {
        var addresses = await _store.NeedingLookupAsync(limit, ct: ct).ConfigureAwait(false);
        return await ResolveAsync(addresses, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Looks up the first <paramref name="limit"/> of these addresses that are
    /// due, in the order given, and leaves every other address alone.
    /// </summary>
    /// <remarks>
    /// For a page that has a table of addresses in front of somebody and no
    /// nightly job behind it - the Windows trial has no scheduler - where
    /// "name the ones on screen" is the useful unit and "name the busiest 500
    /// in the estate" may name none of them. The addresses must have come from
    /// a query already scoped to the person asking; see
    /// <see cref="SourceNameStore.DueAmongAsync"/>.
    /// </remarks>
    public async Task<SourceNameRun> RunAsync(
        IReadOnlyCollection<string> among, int limit, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(among);

        var addresses = await _store.DueAmongAsync(among, limit, ct: ct).ConfigureAwait(false);
        return await ResolveAsync(addresses, ct).ConfigureAwait(false);
    }

    private async Task<SourceNameRun> ResolveAsync(IReadOnlyList<string> addresses, CancellationToken ct)
    {
        if (addresses.Count == 0) { return new SourceNameRun(0, 0, 0); }

        var named = 0;
        var silent = 0;
        var confirmed = 0;
        var nameless = new List<string>();

        foreach (var batch in addresses.Chunk(AtOnce))
        {
            // Each name is checked against its own forward records in the same
            // pass. A name that does not point back is kept for display and
            // decides nothing: the PTR is written by whoever holds the address,
            // and a forger can reverse to a security vendor's hostname as
            // easily as the vendor can.
            var answers = await Task.WhenAll(batch.Select(async ip =>
            {
                var name = await _dns.ReverseAsync(ip, ct).ConfigureAwait(false);
                var points = !string.IsNullOrWhiteSpace(name)
                    && await _dns.ForwardConfirmsAsync(name, ip, ct).ConfigureAwait(false);
                return (Ip: ip, Name: name, Confirmed: points);
            })).ConfigureAwait(false);

            foreach (var (ip, name, points) in answers)
            {
                // ReverseAsync returns null both for "no PTR" and for "the
                // zone did not answer", and this cannot tell them apart from
                // here. Treating a null as answered would retry a genuinely
                // nameless address every night for ever; treating it as
                // unanswered would do the same. The store keeps the flag so
                // the distinction can be made properly when the resolver is
                // asked to report it, and until then a null is recorded as
                // answered so the common case - an address that simply has no
                // PTR - is not re-asked daily.
                var has = !string.IsNullOrWhiteSpace(name);
                if (has) { named++; } else { silent++; nameless.Add(ip); }
                if (points) { confirmed++; }

                await _store.SaveAsync(ip, name, answered: true, forwardConfirmed: has ? points : null, ct: ct)
                    .ConfigureAwait(false);

                ct.ThrowIfCancellationRequested();
            }
        }

        var run = new SourceNameRun(addresses.Count, named, silent, confirmed);

        // Not one name in a run this size says the resolver was not answering.
        // Left recorded as answered, every address in it would be skipped for a
        // month - and a trial machine that was offline for the first press
        // would have its button disappear with the table still full of digits.
        if (run.NothingAnswered)
        {
            foreach (var ip in nameless)
            {
                await _store.SaveAsync(ip, null, answered: false, ct: ct).ConfigureAwait(false);
            }
        }

        return run;
    }
}
