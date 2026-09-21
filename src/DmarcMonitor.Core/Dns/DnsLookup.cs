using System.Net;
using DnsClient;
using DnsClient.Protocol;

namespace DmarcMonitor.Core.Dns;

/// <summary>
/// Reads the records a domain actually publishes.
///
/// Separate from DnsHygiene so the judging is pure and the network is not:
/// every rule can be tested against every combination without a resolver, and
/// this part only has to fetch and be honest about failing.
///
/// Being honest about failing is the point. A timeout looks exactly like an
/// absent record, and an operator told "no DMARC record" for a domain that has
/// one will publish a second over the top of it.
/// </summary>
public sealed class DnsLookup(ILookupClient? client = null)
{
    private readonly ILookupClient _client = client ?? new LookupClient(new LookupClientOptions
    {
        // A resolver that hangs holds up a run over a whole book of clients.
        Timeout = TimeSpan.FromSeconds(5),
        Retries = 2,
        UseCache = true,
    });

    public async Task<PublishedRecords> ReadAsync(string domain, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();

        try
        {
            // The apex query answers two questions at once, so this costs no
            // extra lookup: what TXT records are there, and does the name
            // exist at all. NXDOMAIN comes back as an empty answer section
            // exactly like a domain that simply has no TXT records, and
            // telling those apart is the difference between "publish an SPF
            // record" and "there is no such domain".
            var (apex, apexExists) = await TxtAtApexAsync(name, ct).ConfigureAwait(false);
            if (!apexExists)
            {
                return new PublishedRecords { Domain = name, DomainDoesNotExist = true };
            }

            var dmarc = await TxtAsync($"_dmarc.{name}", ct).ConfigureAwait(false);
            var mtaSts = await TxtAsync($"_mta-sts.{name}", ct).ConfigureAwait(false);
            var tlsRpt = await TxtAsync($"_smtp._tls.{name}", ct).ConfigureAwait(false);

            // Only TXT records that declare themselves SPF count. An apex
            // holds verification tokens for half a dozen services and none of
            // them is an SPF record.
            var spf = apex
                .Where(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var dead = spf.Count > 0
                ? await DeadIncludesAsync(spf[0], ct).ConfigureAwait(false)
                : [];

            // The real cost, not the count of terms in this record. An include
            // spends a lookup and then spends whatever its own record spends,
            // so a record with four terms can cost far more than four.
            //
            // Measured rather than assumed: the large providers vary. Today
            // spf.protection.outlook.com is a flat list of ip4 and ip6 terms
            // and costs one, where it used to nest several includes. That is
            // exactly why this resolves the tree instead of applying a table
            // of known providers, which would be wrong the month after it was
            // written.
            var lookups = spf.Count > 0
                ? await CountLookupsAsync(spf[0], new HashSet<string>(StringComparer.OrdinalIgnoreCase), 0, ct)
                    .ConfigureAwait(false)
                : 0;

            return new PublishedRecords
            {
                Domain = name,
                SpfRecords = spf,
                ApexTxt = apex,
                DmarcRecord = dmarc.FirstOrDefault(t => t.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)),
                MtaStsRecord = mtaSts.FirstOrDefault(t => t.TrimStart().StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase)),
                TlsRptRecord = tlsRpt.FirstOrDefault(t => t.TrimStart().StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase)),
                DeadIncludes = dead,
                SpfLookups = lookups,
            };
        }
        catch (Exception ex) when (ex is DnsResponseException or OperationCanceledException or TimeoutException)
        {
            // Absence and failure are different answers and must not be
            // returned as the same one.
            return new PublishedRecords { Domain = name, LookupFailed = true };
        }
    }

    /// <summary>
    /// Include targets that resolve to no SPF record.
    /// </summary>
    /// <remarks>
    /// One level only. Following the whole tree would need the full
    /// evaluation, and a wrong answer here tells somebody to delete an include
    /// that authorizes their mail. One level catches the common case - a
    /// provider retired, the include left behind - without guessing.
    /// </remarks>
    private async Task<List<string>> DeadIncludesAsync(string spfRecord, CancellationToken ct)
    {
        var dead = new List<string>();

        foreach (var term in SpfRecord.Parse(spfRecord).Terms)
        {
            if (term.Name != "include" || term.Value.Length == 0) { continue; }
            ct.ThrowIfCancellationRequested();

            try
            {
                var txt = await TxtAsync(term.Value, ct).ConfigureAwait(false);
                if (!txt.Any(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)))
                {
                    dead.Add(term.Value);
                }
            }
            catch (DnsResponseException)
            {
                // A lookup that errored is not proof the include is dead, and
                // recommending its removal on that basis could break mail.
            }
        }

        return dead;
    }

    /// <summary>
    /// Every DNS lookup evaluating this record costs, following includes.
    /// </summary>
    /// <remarks>
    /// Depth-capped and cycle-guarded, because a record that includes itself
    /// exists in the wild and this must terminate on it rather than count to
    /// infinity. A lookup that fails stops that branch: counting an
    /// unreachable include as free would understate the total, and
    /// overstating it would have somebody delete a working include.
    /// </remarks>
    private async Task<int> CountLookupsAsync(
        string spfRecord, HashSet<string> visited, int depth, CancellationToken ct)
    {
        // RFC 7208 caps evaluation depth as well as lookup count. Beyond this
        // the record is already broken by any measure.
        if (depth > 10) { return 0; }

        var total = 0;

        foreach (var term in SpfRecord.Parse(spfRecord).Terms)
        {
            if (!term.CostsALookup) { continue; }
            ct.ThrowIfCancellationRequested();

            total++;

            if (term.Name is not ("include" or "redirect") || term.Value.Length == 0) { continue; }
            if (!visited.Add(term.Value)) { continue; }

            try
            {
                var txt = await TxtAsync(term.Value, ct).ConfigureAwait(false);
                var nested = txt.FirstOrDefault(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));
                if (nested is not null)
                {
                    total += await CountLookupsAsync(nested, visited, depth + 1, ct).ConfigureAwait(false);
                }
            }
            catch (DnsResponseException)
            {
                // Unreachable: the term is still counted, its children are not.
            }
        }

        return total;
    }

    /// <summary>
    /// The address ranges an include ends up authorizing, includes followed.
    /// </summary>
    /// <remarks>
    /// Only the ip4 and ip6 terms, because those are the ones an observed
    /// sending address can be tested against. An a or mx term authorizes
    /// whatever those names resolve to today, which is a moving target and
    /// deliberately not followed: a range missed here shows as "no mail seen",
    /// and the finding that produces is worded so that absence is never
    /// treated as permission to delete anything.
    /// </remarks>
    public async Task<IReadOnlyList<AuthorizedRange>> RangesAsync(
        string includeTarget, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(includeTarget);

        var ranges = new List<AuthorizedRange>();
        await CollectAsync(includeTarget, ranges, new HashSet<string>(StringComparer.OrdinalIgnoreCase), 0, ct)
            .ConfigureAwait(false);

        return ranges;
    }

    private async Task CollectAsync(
        string target, List<AuthorizedRange> into, HashSet<string> visited, int depth, CancellationToken ct)
    {
        if (depth > 10 || !visited.Add(target)) { return; }

        string? record;
        try
        {
            var txt = await TxtAsync(target, ct).ConfigureAwait(false);
            record = txt.FirstOrDefault(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));
        }
        catch (DnsResponseException)
        {
            return;
        }

        if (record is null) { return; }

        foreach (var term in SpfRecord.Parse(record).Terms)
        {
            ct.ThrowIfCancellationRequested();

            switch (term.Name)
            {
                case "ip4" or "ip6" when TryNetwork(term.Value, out var network):
                    into.Add(new AuthorizedRange(network));
                    break;

                case "include" or "redirect" when term.Value.Length > 0:
                    await CollectAsync(term.Value, into, visited, depth + 1, ct).ConfigureAwait(false);
                    break;
            }
        }
    }

    /// <summary>Parses an ip4/ip6 value, which may or may not carry a prefix length.</summary>
    private static bool TryNetwork(string value, out IPNetwork network)
    {
        network = default;
        if (value.Length == 0) { return false; }

        // A bare address is a single host, which IPNetwork expresses as a full
        // length prefix. Without this every ip4:192.0.2.1 term is dropped, and
        // dropping ranges makes an include look unused.
        if (!value.Contains('/', StringComparison.Ordinal))
        {
            if (!IPAddress.TryParse(value, out var single)) { return false; }
            var bits = single.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
            network = new IPNetwork(single, bits);
            return true;
        }

        return IPNetwork.TryParse(value, out network);
    }

    /// <summary>
    /// The DKIM key published at one selector, or null when the lookup itself
    /// could not answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null is the third answer and it matters as much here as it does at the
    /// apex. A selector that times out looks exactly like a selector that has
    /// been withdrawn, and the two lead somewhere opposite: one is a network
    /// hiccup, the other is mail about to start failing DKIM. Callers keep
    /// what they already knew when this returns null rather than recording an
    /// absence they did not observe.
    /// </para>
    /// <para>
    /// A name that does not exist is not null, though - it is a real answer,
    /// and it comes back as a key that could not be parsed with "nothing
    /// published at this selector". That is the finding worth having.
    /// </para>
    /// </remarks>
    public async Task<DkimKey?> DkimAsync(string domain, string selector, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(selector);

        var records = await DkimRecordsAsync(domain, selector, ct).ConfigureAwait(false);

        return records is null ? null : DkimKey.Choose(selector, records);
    }

    /// <summary>
    /// Everything published at one selector, before any of it is judged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="DkimAsync"/> answers "what key would a verifier use", which
    /// is the right question nearly everywhere and hides one thing: how many
    /// records are at that name. RFC 6376 §3.6.2.1 does not say which of
    /// several a verifier picks, so a selector carrying two is a key that
    /// works for some receivers and not others - a fault that cannot be seen
    /// from the chosen key alone.
    /// </para>
    /// <para>
    /// Null when the lookup could not answer, as everywhere else here. An
    /// empty list is a real answer: the name resolves to nothing.
    /// </para>
    /// </remarks>
    public async Task<IReadOnlyList<string>?> DkimRecordsAsync(
        string domain, string selector, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(selector);

        var name = $"{selector.Trim().Trim('.')}._domainkey.{domain.Trim().TrimEnd('.')}".ToLowerInvariant();

        try
        {
            return await TxtAsync(name, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is DnsResponseException or OperationCanceledException or TimeoutException)
        {
            return null;
        }
    }

    /// <summary>
    /// The name servers a domain is actually delegated to.
    /// </summary>
    /// <remarks>
    /// Needed to judge the NS records inside a zone file, and useless without
    /// it. A zone export carries whatever NS records the operator has typed
    /// into that provider's panel, which is not the same thing as where the
    /// registrar points the domain - a zone moved from one provider to another
    /// routinely keeps the old provider's NS records inside it, doing nothing,
    /// until somebody moves the domain back and they quietly take effect.
    ///
    /// Empty means "could not tell", never "no name servers". A delegated
    /// domain always has some, so an empty answer is a failed lookup and
    /// nothing may be concluded from it.
    /// </remarks>
    public async Task<IReadOnlyList<string>> NsAsync(string domain, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        try
        {
            var response = await _client
                .QueryAsync(domain.Trim().TrimEnd('.'), QueryType.NS, cancellationToken: ct)
                .ConfigureAwait(false);

            return [.. response.Answers.NsRecords()
                .Select(r => r.NSDName.Value.TrimEnd('.').ToLowerInvariant())
                .Where(host => host.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)];
        }
        catch (Exception ex) when (ex is DnsResponseException or OperationCanceledException or TimeoutException)
        {
            return [];
        }
    }

    /// <summary>
    /// The mail exchangers a domain publishes, best preference first.
    /// </summary>
    /// <remarks>
    /// Needed to write an MTA-STS policy, which lists the hosts a sender is
    /// allowed to deliver to. Getting this list wrong in enforce mode does not
    /// degrade anything gracefully: a sender that cannot match the host it
    /// reached against the policy refuses to deliver at all.
    /// </remarks>
    public async Task<IReadOnlyList<string>> MxAsync(string domain, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        try
        {
            var response = await _client
                .QueryAsync(domain.Trim().TrimEnd('.'), QueryType.MX, cancellationToken: ct)
                .ConfigureAwait(false);

            return [.. response.Answers.MxRecords()
                .OrderBy(r => r.Preference)
                .Select(r => r.Exchange.Value.TrimEnd('.').ToLowerInvariant())
                .Where(host => host.Length > 0)
                .Distinct(StringComparer.Ordinal)];
        }
        catch (Exception ex) when (ex is DnsResponseException or OperationCanceledException or TimeoutException)
        {
            // Empty means "could not tell", and every caller treats that as a
            // reason to refuse rather than as a domain with no mail servers.
            return [];
        }
    }

    /// <summary>
    /// The apex TXT records, and whether the name exists at all.
    /// </summary>
    /// <remarks>
    /// Errors are not thrown by this client by default, so an NXDOMAIN
    /// arrives as an ordinary response carrying the code and no answers. Read
    /// here rather than inferred from emptiness, which cannot tell a domain
    /// that does not exist from one that publishes no TXT records.
    /// </remarks>
    private async Task<(List<string> Records, bool Exists)> TxtAtApexAsync(string name, CancellationToken ct)
    {
        var response = await _client.QueryAsync(name, QueryType.TXT, cancellationToken: ct).ConfigureAwait(false);

        if (response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain)
        {
            return ([], false);
        }

        return ([.. response.Answers.TxtRecords().Select(r => string.Concat(r.Text))], true);
    }

    private async Task<List<string>> TxtAsync(string name, CancellationToken ct)
    {
        var response = await _client.QueryAsync(name, QueryType.TXT, cancellationToken: ct).ConfigureAwait(false);

        // A TXT record longer than 255 characters arrives as several strings
        // that must be joined with nothing between them. Long SPF records and
        // DKIM keys are routinely split this way, and joining with a space
        // corrupts them.
        return [.. response.Answers.TxtRecords().Select(r => string.Concat(r.Text))];
    }
}
