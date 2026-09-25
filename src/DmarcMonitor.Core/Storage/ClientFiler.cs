namespace DmarcMonitor.Core.Storage;

/// <summary>One domain, and where it would be filed.</summary>
/// <param name="Domain">The domain itself.</param>
/// <param name="Name">The client it goes under.</param>
/// <param name="Slug">That client's slug, which goes into report filenames and is permanent.</param>
/// <param name="Existing">True when the client is already there and only the domain moves.</param>
/// <param name="Skipped">Why this one was left alone, or empty when it was not.</param>
public sealed record FilingPlan(
    string Domain, string Name, string Slug, bool Existing = false, string Skipped = "")
{
    public bool WasSkipped => Skipped.Length > 0;
}

/// <summary>What one filing run did, or would do.</summary>
public sealed record FilingResult(IReadOnlyList<FilingPlan> Planned)
{
    public IReadOnlyList<FilingPlan> Filed => [.. Planned.Where(p => !p.WasSkipped)];
    public IReadOnlyList<FilingPlan> Skipped => [.. Planned.Where(p => p.WasSkipped)];

    /// <summary>Clients this run would create, rather than domains it would move.</summary>
    public int NewClients => Filed.Count(p => !p.Existing);

    public bool DidAnything => Filed.Count > 0;
}

/// <summary>
/// Files domains nobody has assigned under a client of their own.
/// </summary>
/// <remarks>
/// <para>
/// An import of a real mailbox arrives with seventeen domains in it and files
/// every one of them under Unassigned, because the product has no way of
/// knowing whose they are. Somebody then creates seventeen clients by hand and
/// assigns seventeen domains, which is the work the import just proved it
/// could do itself: the domain IS the grouping until a person says otherwise.
/// </para>
/// <para>
/// The name is the domain, deliberately. Deriving "CLIENT-A" from client-a.example is
/// a guess that reads as confident, and the one thing that must not be guessed
/// is the name on a client's report - so it starts as the domain, which is
/// true, and gets renamed by somebody who knows. The slug is permanent because
/// it goes into report filenames, so it is derived once, here, from the domain.
/// </para>
/// <para>
/// A subdomain joins its parent's client rather than starting a new one, and
/// the parent is looked for among domains this install already has rather than
/// worked out from the name. That sidesteps the public suffix list entirely:
/// no table of co.uk and com.au to keep current, and no chance of filing two
/// unrelated customers together because a suffix was missing from it.
/// </para>
/// </remarks>
public static class ClientFiler
{
    /// <summary>
    /// Works out where each unassigned domain would go, writing nothing.
    /// </summary>
    /// <param name="store">The store to read. Its organization scopes the run.</param>
    /// <param name="tenantId">One organization, or null for the store's own.</param>
    public static async Task<FilingResult> PlanAsync(
        ReportStore store, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(store);

        var unassigned = await store.GetUnassignedDomainsAsync(tenantId, ct).ConfigureAwait(false);
        if (unassigned.Count == 0) { return new FilingResult([]); }

        var clients = await store.GetClientsAsync(tenantId, ct).ConfigureAwait(false);

        // Slug to name, for the collision check. Built a pair at a time rather
        // than with ToDictionary: a slug is unique within an organization and
        // not across them, every organization carries its own "unassigned",
        // and ToDictionary threw on the second one.
        var taken = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var client in clients) { taken[client.Slug] = client.Name; }

        // Where each domain already filed lives, so a subdomain can join it.
        // Unassigned ones are left out: they are what this run is deciding,
        // and a domain sitting in Unassigned is not a parent to inherit from.
        var filedDomains = new Dictionary<string, (string Name, string Slug)>(StringComparer.OrdinalIgnoreCase);
        foreach (var summary in await store.GetDomainsAsync(tenantId, ct).ConfigureAwait(false))
        {
            if (summary.ClientSlug.Equals(ReportStore.UnassignedClientSlug, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            filedDomains[summary.Domain] = (summary.ClientName, summary.ClientSlug);
        }

        var planned = new List<FilingPlan>();

        // Shortest first, so acme.com is filed before mail.acme.com and the
        // subdomain can find the parent this same run created.
        foreach (var domain in unassigned.OrderBy(d => d.Length).ThenBy(d => d, StringComparer.Ordinal))
        {
            if (ParentOf(domain, filedDomains) is { } parent)
            {
                planned.Add(new FilingPlan(domain, parent.Name, parent.Slug, Existing: true));
                filedDomains[domain] = parent;
                continue;
            }

            var slug = ReportStore.Slugify(domain);
            if (slug.Length == 0)
            {
                planned.Add(new FilingPlan(domain, domain, "", Skipped: "its name does not reduce to a slug"));
                continue;
            }

            // Nothing should collide when the name IS the domain, but a domain
            // that folds onto an existing slug would quietly file two
            // customers together - and that is not a thing to discover from a
            // client's report.
            if (taken.TryGetValue(slug, out var owner) && !owner.Equals(domain, StringComparison.OrdinalIgnoreCase))
            {
                planned.Add(new FilingPlan(
                    domain, domain, slug, Skipped: $"'{slug}' is already '{owner}'"));
                continue;
            }

            taken[slug] = domain;
            filedDomains[domain] = (domain, slug);
            planned.Add(new FilingPlan(domain, domain, slug));
        }

        return new FilingResult(planned);
    }

    /// <summary>
    /// Files them, creating a client where there is not one already.
    /// </summary>
    /// <remarks>
    /// Returns what it actually did rather than what it planned: a client that
    /// could not be created drops out, so the caller's count and the database
    /// agree.
    /// </remarks>
    public static async Task<FilingResult> ApplyAsync(
        ReportStore store, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(store);

        var plan = await PlanAsync(store, tenantId, ct).ConfigureAwait(false);
        if (!plan.DidAnything) { return plan; }

        var done = new List<FilingPlan>(plan.Skipped);

        foreach (var item in plan.Filed)
        {
            ct.ThrowIfCancellationRequested();

            if (!item.Existing)
            {
                var created = await store.CreateClientAsync(item.Name, item.Slug, ct: ct).ConfigureAwait(false);
                if (created is null)
                {
                    done.Add(item with { Skipped = "the client could not be created" });
                    continue;
                }
            }

            var outcome = await store.AssignDomainAsync(item.Domain, item.Slug, tenantId, ct).ConfigureAwait(false);
            done.Add(outcome == ReportStore.AssignOutcome.Assigned
                ? item
                : item with { Skipped = $"the domain could not be assigned ({outcome})" });
        }

        return new FilingResult(done);
    }

    /// <summary>
    /// The client of the nearest ancestor domain this install already has.
    /// </summary>
    /// <remarks>
    /// Walked label by label from the left, so mail.eu.acme.com finds
    /// eu.acme.com before acme.com. Only domains that are really here can
    /// match, which is what makes this safe without a suffix list: "co.uk" is
    /// never a parent because nobody's install has co.uk as a domain of its
    /// own.
    /// </remarks>
    private static (string Name, string Slug)? ParentOf(
        string domain, Dictionary<string, (string Name, string Slug)> filed)
    {
        var rest = domain;

        while (rest.IndexOf('.', StringComparison.Ordinal) is var dot and > 0)
        {
            rest = rest[(dot + 1)..];
            if (rest.IndexOf('.', StringComparison.Ordinal) < 0) { return null; }   // a bare TLD is nobody's parent
            if (filed.TryGetValue(rest, out var owner)) { return owner; }
        }

        return null;
    }
}
