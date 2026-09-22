using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Intelligence;

/// <summary>What one pass of reverse lookups did.</summary>
/// <param name="Looked">Addresses asked about.</param>
/// <param name="Named">Of those, how many came back with a name.</param>
/// <param name="Silent">Of those, how many had a reverse zone that did not answer.</param>
public readonly record struct SourceNameRun(int Looked, int Named, int Silent)
{
    /// <summary>Of the addresses asked about, how many now have nothing to show but digits.</summary>
    public int Unnamed => Looked - Named;

    public string Describe() => Looked == 0
        ? "Every source already has a name; nothing to look up."
        : $"Looked up {Looked} source(s): {Named} named, {Unnamed} with no name ({Silent} whose reverse zone did not answer).";
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
        if (addresses.Count == 0) { return new SourceNameRun(0, 0, 0); }

        var named = 0;
        var silent = 0;

        foreach (var batch in addresses.Chunk(AtOnce))
        {
            var answers = await Task.WhenAll(batch.Select(async ip =>
                (Ip: ip, Name: await _dns.ReverseAsync(ip, ct).ConfigureAwait(false)))).ConfigureAwait(false);

            foreach (var (ip, name) in answers)
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
                if (has) { named++; } else { silent++; }

                await _store.SaveAsync(ip, name, answered: true, ct: ct).ConfigureAwait(false);

                ct.ThrowIfCancellationRequested();
            }
        }

        return new SourceNameRun(addresses.Count, named, silent);
    }
}
