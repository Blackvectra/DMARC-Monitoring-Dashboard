namespace DmarcMonitor.Core.Rollout;

/// <summary>The columns the domains table can be ordered by.</summary>
public enum DomainSort
{
    /// <summary>By name, which is also what puts a client's domains next to each other.</summary>
    Domain,

    /// <summary>How urgent: the order the dashboard ranks them in.</summary>
    Status,

    /// <summary>How strict the published policy is: none, quarantine, reject.</summary>
    Policy,

    Volume,

    /// <summary>The share of mail that passed. A domain with no mail has no rate and sorts last.</summary>
    Passing,

    Sources,
    LastReport,
}

/// <summary>
/// One line of the domains table: either a client's heading, or a domain.
/// </summary>
public sealed record DomainLine
{
    /// <summary>The domain on this line, or null when the line is a heading.</summary>
    public DomainTriage? Row { get; init; }

    /// <summary>The client a block of domains belongs to, on the line that opens the block.</summary>
    public string? Heading { get; init; }

    /// <summary>How many domains the block holds. Only meaningful on a heading.</summary>
    public int Count { get; init; }

    /// <summary>
    /// What tells this heading from every other: the client, not the words on
    /// it. Two clients can share a name, and a page that keyed its rows by the
    /// heading's text would be handed the same key twice.
    /// </summary>
    public string? Key { get; init; }

    /// <summary>True for a domain inside a block that has a heading, so it need not name its client.</summary>
    public bool Headed { get; init; }
}

/// <summary>
/// Orders and groups the domains table.
///
/// Pure, and in Core, because "which domain comes next" is the whole of what
/// the table is for and a rule that decides it should be one a test can reach.
/// </summary>
public static class DomainList
{
    /// <summary>
    /// Which way a column runs the first time somebody presses it.
    /// </summary>
    /// <remarks>
    /// The way they are asking for. Pressing "Volume" wants the busiest;
    /// pressing "Passing" wants the worst, which is the lowest; pressing "Last
    /// report" wants whoever has gone quiet, which is the oldest; pressing
    /// "Policy" wants whoever is still at none. A header that opened on the
    /// order nobody asked for would be pressed twice every time.
    /// </remarks>
    /// <returns>True when the first press runs from the largest down.</returns>
    public static bool StartsDescending(DomainSort sort) =>
        sort is DomainSort.Status or DomainSort.Volume or DomainSort.Sources;

    /// <summary>
    /// Whether putting a client's domains together would show anything: there
    /// is more than one client among these, and at least one of them has more
    /// than one domain.
    /// </summary>
    /// <remarks>
    /// Asked of the domains in view and not of every client an organization
    /// has. A customer's login sees its own domains only, and whether it is
    /// offered a way to group them must not turn on how many domains somebody
    /// else's clients have.
    /// </remarks>
    public static bool CanGroup(IEnumerable<DomainTriage> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var clients = rows.GroupBy(r => (r.TenantId, r.ClientSlug)).ToList();
        return clients.Count > 1 && clients.Any(g => g.Count() > 1);
    }

    /// <summary>
    /// The table as it should be drawn.
    /// </summary>
    /// <param name="rows">The domains to show, already filtered.</param>
    /// <param name="sort">The column to order by.</param>
    /// <param name="descending">True for largest first; for Status that is the most urgent first.</param>
    /// <param name="grouped">
    /// Put a client's domains together under a heading. Only when ordered by
    /// domain: ordered by anything else the table is one list, because a
    /// reader who pressed "Passing" is asking which domains are worst across
    /// every client, not which are worst within each.
    /// </param>
    /// <param name="acrossOrganizations">
    /// A master looking at several organizations, where two clients of the same
    /// name in different ones are not the same client.
    /// </param>
    public static IReadOnlyList<DomainLine> Layout(
        IEnumerable<DomainTriage> rows, DomainSort sort, bool descending, bool grouped, bool acrossOrganizations)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var ordered = Order(rows, sort, descending);

        if (!grouped || sort != DomainSort.Domain)
        {
            return [.. ordered.Select(r => new DomainLine { Row = r })];
        }

        // A block sits where its first domain would, so the table stays in
        // the order its header says and a client's other domains are simply
        // pulled up beside it. Ordered by the client's name instead, a table
        // headed "Domain" would not be in domain order.
        var blocks = new List<List<DomainTriage>>();
        var byClient = new Dictionary<string, List<DomainTriage>>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in ordered)
        {
            var key = ClientKey(row, acrossOrganizations);
            if (!byClient.TryGetValue(key, out var block))
            {
                byClient[key] = block = [];
                blocks.Add(block);
            }

            block.Add(row);
        }

        var lines = new List<DomainLine>(ordered.Count + blocks.Count);

        foreach (var block in blocks)
        {
            var key = ClientKey(block[0], acrossOrganizations);

            // One domain needs no heading: the client is the domain, or the
            // domain is the only thing the client has, and a heading over a
            // single row is a row said twice.
            if (block.Count < 2)
            {
                lines.Add(new DomainLine { Row = block[0] });
                continue;
            }

            lines.Add(new DomainLine { Heading = ClientName(block[0], acrossOrganizations), Count = block.Count, Key = key });
            lines.AddRange(block.Select(r => new DomainLine { Row = r, Headed = true }));
        }

        return lines;
    }

    /// <summary>Orders domains, ties always the same way so equal rows never reshuffle.</summary>
    /// <remarks>
    /// Ties fall to the name, and to who owns it when two organizations manage
    /// the same one; neither flips with the direction. Between two equally
    /// urgent domains, the one losing more mail comes first, as it does on the
    /// dashboard.
    /// </remarks>
    public static IReadOnlyList<DomainTriage> Order(IEnumerable<DomainTriage> rows, DomainSort sort, bool descending)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var sign = descending ? -1 : 1;
        var list = rows.ToList();

        list.Sort((a, b) =>
        {
            // No mail means no pass rate, and a rate of 0% would put the
            // quiet domains first when somebody asks for the worst. They go
            // last whichever way the column runs.
            if (sort == DomainSort.Passing && (a.Messages == 0) != (b.Messages == 0))
            {
                return a.Messages == 0 ? 1 : -1;
            }

            var primary = Primary(a, b, sort);
            if (primary != 0) { return sign * primary; }

            if (sort == DomainSort.Status)
            {
                var lost = b.Failing.CompareTo(a.Failing);
                if (lost != 0) { return lost; }
            }

            var name = string.Compare(a.Domain, b.Domain, StringComparison.OrdinalIgnoreCase);
            if (name != 0) { return name; }

            // One domain name can belong to two organizations, and the list can
            // be sorted unstably: without this, equal rows may swap on a redraw.
            var organization = string.Compare(a.Organization, b.Organization, StringComparison.OrdinalIgnoreCase);
            if (organization != 0) { return organization; }

            var tenant = string.CompareOrdinal(a.TenantId, b.TenantId);
            return tenant != 0 ? tenant : string.CompareOrdinal(a.ClientSlug, b.ClientSlug);
        });

        return list;
    }

    private static int Primary(DomainTriage a, DomainTriage b, DomainSort sort) => sort switch
    {
        DomainSort.Domain => string.Compare(a.Domain, b.Domain, StringComparison.OrdinalIgnoreCase),
        DomainSort.Status => a.Level.CompareTo(b.Level),
        DomainSort.Policy => Strictness(a.Policy).CompareTo(Strictness(b.Policy)),
        DomainSort.Volume => a.Messages.CompareTo(b.Messages),
        DomainSort.Passing => a.PassRate.CompareTo(b.PassRate),
        DomainSort.Sources => a.Sources.CompareTo(b.Sources),

        // Never reported sorts as the oldest, so "stalest first" opens with
        // the domains that have never sent a report at all.
        DomainSort.LastReport => Nullable.Compare(a.LastReport, b.LastReport),
        _ => 0,
    };

    private static int Strictness(string policy) => policy switch
    {
        "reject" => 2,
        "quarantine" => 1,
        _ => 0,
    };

    /// <summary>Whom a domain's block is named for, "Unassigned" for a domain nobody has filed.</summary>
    private static string ClientName(DomainTriage row, bool acrossOrganizations) =>
        (acrossOrganizations && !string.IsNullOrWhiteSpace(row.Organization) ? row.Organization + " / " : "")
        + (string.IsNullOrWhiteSpace(row.ClientName) ? "Unassigned" : row.ClientName);

    /// <summary>
    /// What makes two domains one client: the client itself, not its name.
    /// </summary>
    /// <remarks>
    /// The slug where there is one, because two clients can share a name; the
    /// organization too when looking across several, because two organizations
    /// can each have a client of the same slug. The organization by its
    /// identity: two can also share a name, and keyed by the name their
    /// same-slugged clients were one block under one heading.
    /// </remarks>
    private static string ClientKey(DomainTriage row, bool acrossOrganizations) =>
        (acrossOrganizations ? (row.TenantId.Length > 0 ? row.TenantId : row.Organization) : "") + "\u001f"
        + (row.ClientSlug.Length > 0 ? row.ClientSlug : ClientName(row, acrossOrganizations));
}
