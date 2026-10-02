namespace DmarcMonitor.Core.Intelligence;

/// <summary>
/// One sender: every failing address that belongs to the same operator, read as
/// a single row.
/// </summary>
/// <remarks>
/// <para>
/// From a real import of 83 reports over 17 domains, the sources list reported
/// four separate findings:
/// </para>
/// <code>
///   192.0.2.10   192-0-2-10-host.colocrossing.com   client-c.example
///   192.0.2.11   192-0-2-11-host.colocrossing.com   client-b.example
///   192.0.2.12   192-0-2-12-host.colocrossing.com   client-b.example
///   192.0.2.13   192-0-2-13-host.colocrossing.com   client-a.example
/// </code>
/// <para>
/// One hosting provider, four addresses, three unrelated customers. As four
/// rows each is noise; as one sender working through the estate it is the
/// pattern only a multi-client platform can see - and the per-address view
/// misses it entirely, because changing address between customers costs
/// nothing on a VPS host.
/// </para>
/// <para>
/// The same grouping also folds the fourteen addresses a mail provider
/// answers from into one row rather than fourteen. The addresses are kept
/// either way: they are the identity, and blocking is done by address.
/// </para>
/// <para>
/// A pure function of the rows the list already returns - no query, no
/// schema, no network - so it can be tested against the exact shapes that came
/// out of a real estate.
/// </para>
/// </remarks>
public sealed class SenderGroup
{
    private SenderGroup(string key, string name, string? domain, SourceKind kind, IReadOnlyList<FailingSource> sources)
    {
        Key = key;
        Name = name;
        Domain = domain;
        Kind = kind;
        Sources = sources;

        FailedMessages = sources.Sum(s => s.FailedMessages);
        Domains = [.. sources.SelectMany(s => s.Domains).Distinct(StringComparer.OrdinalIgnoreCase)
                             .OrderBy(d => d, StringComparer.Ordinal)];
        Clients = [.. sources.SelectMany(s => s.Clients).Distinct(StringComparer.OrdinalIgnoreCase)
                             .OrderBy(c => c, StringComparer.Ordinal)];
        LastSeen = sources.Where(s => s.LastSeen is not null).Max(s => s.LastSeen);
        Verdict = sources.Max(s => s.Verdict);
        Reading = sources.Max(s => s.Reading);

        // The union where the rows carry it, the largest count where they do
        // not. Never a sum: two addresses that both hit one client reached
        // one party.
        IndependentParties = sources.Any(s => s.PartyKeys.Count > 0)
            ? sources.SelectMany(s => s.PartyKeys).Distinct(StringComparer.OrdinalIgnoreCase).Count()
            : sources.Max(s => s.IndependentParties);
    }

    /// <summary>What identifies the group: stable between renders, unique within a list.</summary>
    public string Key { get; }

    /// <summary>
    /// What to call it: the vendor when every address is confirmed as the
    /// vendor's, else the domain the names share, else for a lone address
    /// whatever <see cref="FailingSource.Display"/> prints.
    /// </summary>
    public string Name { get; }

    /// <summary>The registrable domain the addresses' names share, e.g. colocrossing.com. Null for a lone address.</summary>
    public string? Domain { get; }

    /// <summary>What the catalogue says it is, when every address is confirmed as that vendor's.</summary>
    public SourceKind Kind { get; }

    /// <summary>The addresses, exactly as the per-source list has them.</summary>
    public IReadOnlyList<FailingSource> Sources { get; }

    public bool IsGroup => Sources.Count > 1;
    public int AddressCount => Sources.Count;
    public long FailedMessages { get; }
    public IReadOnlyList<string> Domains { get; }
    public IReadOnlyList<string> Clients { get; }
    public DateTimeOffset? LastSeen { get; }

    /// <summary>How many unrelated parties the sender reached, counted once each.</summary>
    public int IndependentParties { get; }

    /// <summary>
    /// The worst verdict any of its addresses earned.
    /// </summary>
    /// <remarks>
    /// The group does not get a softer reading than its members. One address
    /// authenticating for itself does not excuse the three beside it that
    /// authenticated nothing.
    /// </remarks>
    public SourceVerdict Verdict { get; }

    /// <summary>The worst reading among its addresses; see <see cref="FailingSource.Reading"/>.</summary>
    public SourceReading Reading { get; }

    /// <summary>
    /// Several addresses at one operator, reaching parties that have nothing to
    /// do with each other.
    /// </summary>
    /// <remarks>
    /// Two things deliberately do not count. A mail provider is
    /// infrastructure, not an actor: grouping every Microsoft address
    /// produces "Microsoft 365, nine clients" on every estate on earth, which
    /// is true, useless and would head the list for ever. And several
    /// addresses at one host against ONE party is ordinary - it is what a
    /// mail provider looks like to one customer. Gateways do count: one
    /// breaking signatures across five customers is a real finding, and one an
    /// MSP is uniquely placed to notice.
    ///
    /// Parties rather than domains: one client with two domains is one party,
    /// and an operator that hit both is not working through a list.
    /// </remarks>
    public bool SpansClients => IsGroup && Kind != SourceKind.MailProvider && IndependentParties > 1;

    /// <summary>
    /// Groups failing sources by who operates them.
    /// </summary>
    /// <param name="sources">The per-address rows.</param>
    /// <param name="group">False to keep every address as a row of its own.</param>
    /// <remarks>
    /// <para>
    /// Grouped by the domain each address's name CLAIMS, not only by the ones
    /// it proves. A host's reverse names often have no forward records at all
    /// - ColoCrossing's do not - and grouping only the confirmed ones would
    /// take exactly the pattern this exists to show off the page. What is
    /// restricted is what the group is called: the vendor's name only when
    /// every address in it is confirmed as the vendor's, because one claimant
    /// in a group and "INKY" would vouch for the claim.
    /// </para>
    /// <para>
    /// A confirmed mail provider is peeled off into a group of its own, so an
    /// address that merely claims to be outlook.com is never lost inside the
    /// real ones - nor, the other way, hidden from the page because it said it
    /// was Microsoft.
    /// </para>
    /// <para>
    /// Names that reduce to a reverse zone (<c>in-addr.arpa</c>) say nothing
    /// about an operator and are never grouped on; each such address stays a
    /// row of its own.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<SenderGroup> Build(IEnumerable<FailingSource> sources, bool group = true)
    {
        ArgumentNullException.ThrowIfNull(sources);

        var buckets = new Dictionary<string, List<FailingSource>>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var source in sources)
        {
            var key = group ? KeyOf(source) : $"ip:{source.SourceIp}";
            if (!buckets.TryGetValue(key, out var members))
            {
                buckets[key] = members = [];
                order.Add(key);
            }

            members.Add(source);
        }

        var result = new List<SenderGroup>(order.Count);

        foreach (var key in order)
        {
            var members = buckets[key];

            if (members.Count == 1)
            {
                var only = members[0];
                result.Add(new SenderGroup(
                    key, only.Display, null,
                    SourceCatalog.Identify(only.VerifiedName)?.Kind ?? SourceKind.Unknown, members));
                continue;
            }

            // Null only for a list that names one address twice, which the
            // query cannot produce; the address then stands in for the domain
            // rather than the page failing to draw.
            var domain = SourceCatalog.OrganizationalDomain(members[0].ReverseName);

            // Named for the vendor only when every address in it is confirmed
            // as the vendor's. One unconfirmed member is a claim, and naming
            // the row "INKY" would vouch for it.
            var identity = members.All(m => m.NameConfirmed)
                ? SourceCatalog.Identify(members[0].ReverseName)
                : null;

            result.Add(new SenderGroup(
                key, identity?.Name ?? domain ?? members[0].Display, domain, identity?.Kind ?? SourceKind.Unknown, members));
        }

        return result;
    }

    /// <summary>Smaller than zero when <paramref name="a"/> sorts first ascending.</summary>
    private static int Primary(SenderGroup a, SenderGroup b, SenderSort sort)
    {
        switch (sort)
        {
            case SenderSort.Severity:
                var reading = a.Reading.CompareTo(b.Reading);
                return reading != 0 ? reading : a.SpansClients.CompareTo(b.SpansClients);

            case SenderSort.Sender:
                return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);

            case SenderSort.Failed:
                return a.FailedMessages.CompareTo(b.FailedMessages);

            case SenderSort.Reach:
                return a.IndependentParties.CompareTo(b.IndependentParties);

            // Never seen sorts as the oldest, so the unknown end up at the
            // bottom of "newest first" rather than the top.
            case SenderSort.LastSeen:
                return Nullable.Compare(a.LastSeen, b.LastSeen);

            default:
                return 0;
        }
    }

    private static string KeyOf(FailingSource source)
    {
        var domain = SourceCatalog.OrganizationalDomain(source.ReverseName);

        // Nothing to group on. A reverse zone is not an operator: without this
        // every address whose PTR is only its own reverse name falls into one
        // bucket per leading octet.
        if (domain is null || domain.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase))
        {
            return $"ip:{source.SourceIp}";
        }

        // Infrastructure rather than an actor, but only where the name is
        // confirmed. Grouping is by the domain each address CLAIMS, and a
        // sender forging mail can reverse to something.outlook.com. Keyed by
        // the vendor rather than the domain so google.com and googlemail.com
        // are one row.
        if (source.NameConfirmed && SourceCatalog.Identify(source.ReverseName) is { Kind: SourceKind.MailProvider } provider)
        {
            return $"provider:{provider.Name}";
        }

        return $"domain:{domain}";
    }

    /// <summary>
    /// Sorts senders. Ties always fall back to the same order whichever way
    /// the column runs, so a list does not reshuffle its equal rows when the
    /// direction flips.
    /// </summary>
    /// <param name="descending">
    /// True for largest first. For <see cref="SenderSort.Severity"/> that is
    /// the most worrying first, which is the order the page opens in.
    /// </param>
    public static IReadOnlyList<SenderGroup> Order(IEnumerable<SenderGroup> groups, SenderSort sort, bool descending)
    {
        ArgumentNullException.ThrowIfNull(groups);

        var sign = descending ? -1 : 1;
        var list = groups.ToList();

        list.Sort((a, b) =>
        {
            var primary = Primary(a, b, sort);
            if (primary != 0) { return sign * primary; }

            // Reach, then volume, then name: an operator against five
            // customers matters more than one against two, whatever the
            // message counts say.
            var reach = b.IndependentParties.CompareTo(a.IndependentParties);
            if (reach != 0) { return reach; }

            var volume = b.FailedMessages.CompareTo(a.FailedMessages);
            if (volume != 0) { return volume; }

            var name = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            return name != 0 ? name : string.CompareOrdinal(a.Key, b.Key);
        });

        return list;
    }
}

/// <summary>The columns a list of senders can be ordered by.</summary>
public enum SenderSort
{
    /// <summary>How worrying: the worst reading first, then whether it spans clients.</summary>
    Severity,

    Sender,
    Failed,

    /// <summary>How many unrelated parties it reached.</summary>
    Reach,

    LastSeen,
}
