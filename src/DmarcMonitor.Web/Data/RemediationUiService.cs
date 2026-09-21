using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Rollout;

namespace DmarcMonitor.Web.Data;

/// <summary>One domain on the Fix page: what it publishes, what the reports say, what could change.</summary>
public sealed record DomainFixes(
    string Domain,
    string ClientName,
    PublishedRecords Published,
    DomainTriage? Triage,
    IReadOnlyList<ChangePlan> Plans,
    string ProviderName,
    bool CanApply,
    string? ProviderError)
{
    /// <summary>
    /// The transport-security records this domain needs, whether or not any
    /// of them can be applied from here.
    /// </summary>
    /// <remarks>
    /// Separate from Plans, which is what the product would CHANGE. A domain
    /// with no MTA-STS at all has nothing to change and everything to do, and
    /// it used to get a page that said nothing whatsoever about it.
    /// </remarks>
    public IReadOnlyList<RecordToPublish> TransportRecords { get; init; } = [];

    /// <summary>The policy file behind the CNAME, when there is one to serve.</summary>
    public string PolicyFile { get; init; } = "";

    /// <summary>True when nobody has said where this instance is reachable.</summary>
    public bool PolicyHostUnknown { get; init; }

    /// <summary>The policy the reports say the domain is ready for, or null.</summary>
    public string? ReadyFor
    {
        get
        {
            var headline = Triage?.Headline ?? "";
            var at = headline.IndexOf("Ready to move to p=", StringComparison.Ordinal);
            return at < 0 ? null : headline[(at + "Ready to move to p=".Length)..].TrimEnd('.');
        }
    }

    public string CurrentPolicy => DmarcRecord.Parse(Published.DmarcRecord) is { IsValid: true } r ? r.Policy : "";
}

/// <summary>
/// The third write path, and the one that reaches outside the machine: it
/// changes a customer's DNS.
///
/// The same guardrails as the command line, because they are the same code.
/// Nothing here writes without a person clicking a button that says so and
/// giving a reason, and every write is the audit row the client's report
/// prints. Plans shown on the page are computed and not stored; only an
/// apply stores its plan, so browsing the page does not fill the table with
/// looks.
/// </summary>
public sealed class RemediationUiService(
    DatabaseInfo database,
    DnsLookup lookup,
    RemediationService remediation,
    DnsProviderConfigs providers,
    MtaStsFetcher mtaSts,
    IConfiguration configuration)
{
    private readonly TriageService _triage = new(database.Path);
    private readonly MtaStsStore _policies = new(database.Path);

    public string SecretsDescription => providers.Secrets.Description;
    public bool SecretsAvailable => providers.Secrets.IsAvailable;

    /// <summary>
    /// Every domain worth planning for, straight from the database.
    /// </summary>
    /// <remarks>
    /// Separate from the planning because this is instant and planning is
    /// not: the page lists the domains at once and fills each in as its DNS
    /// comes back, rather than showing nothing for the half-minute it takes
    /// to ask about ten domains.
    /// </remarks>
    /// <param name="tenantId">One organization's domains, or null for every organization's.</param>
    public Task<IReadOnlyList<DomainTriage>> DomainsAsync(string? tenantId, string? clientSlug = null, CancellationToken ct = default) =>
        _triage.GetAsync(tenantId: tenantId, clientSlug: clientSlug, ct: ct);

    /// <summary>
    /// One domain, with the safe fixes and optionally a policy move planned.
    /// </summary>
    /// <remarks>
    /// The triage row is the proof the caller may see this domain: it came
    /// from a scoped list. Without one, the domain is looked up within the
    /// same scope and a domain outside it plans nothing.
    /// </remarks>
    public async Task<DomainFixes> PlanAsync(
        string domain, DomainTriage? triage, string? policy, string? tenantId = null, CancellationToken ct = default)
    {
        triage ??= (await _triage.GetAsync(tenantId: tenantId, ct: ct))
            .FirstOrDefault(t => t.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
        var published = await lookup.ReadAsync(domain, ct);
        var plans = new List<ChangePlan>();

        IReadOnlyList<RecordToPublish> transportRecords = [];
        var policyFile = "";
        var policyHostUnknown = false;

        // Nothing is planned from a failed read: "no record" and "could not
        // read" would plan opposite things.
        if (!published.LookupFailed)
        {
            if (policy is not null)
            {
                plans.Add(DmarcPolicyPlanner.Advance(domain, published.DmarcRecord, policy));
            }

            var sp = DmarcPolicyPlanner.FixSubdomainPolicy(domain, published.DmarcRecord);
            if (!sp.IsNoop) { plans.Add(sp); }

            var spf = published.SpfRecords.Count > 0 ? published.SpfRecords[0] : null;
            plans.AddRange(published.DeadIncludes.Select(dead => SpfIncludePlanner.RemoveDeadInclude(domain, spf, dead)));

            // Transport security. TLS-RPT only when there is somewhere to send
            // the reports; without a configured address this would plan a
            // record pointing at a mailbox nobody reads.
            if (configuration["Reporting:TlsReportAddress"] is { Length: > 0 } tlsTo)
            {
                var tls = TransportPlanner.TlsReporting(domain, published.TlsRptRecord, tlsTo);
                if (!tls.IsNoop) { plans.Add(tls); }
            }

            // MTA-STS is only ever announced for a policy already being
            // served, so the file is fetched rather than assumed. Skipped
            // entirely for a domain with neither, which is not a fault - it
            // is a domain nobody has set this up for.
            // The id comes from this product's record of the policy, not from
            // the fetched file - RFC 8461 policy files do not carry it. Fetch
            // without it and every plan announces "v=STSv1; id=", which is not
            // a record a sender will accept.
            var known = await _policies.GetAsync(domain, ct);

            // Fetched only when there is a reason to think a policy exists.
            //
            // The fetch is an HTTPS request to mta-sts.<domain>, which for a
            // domain nobody has set this up for is a name that does not
            // resolve - so it costs a DNS failure and several hundred
            // milliseconds to learn nothing. Seventeen of eighteen domains on
            // the real database are in exactly that state, and the Fix page
            // paid for all of them on every load.
            //
            // Skipped only when BOTH are absent: no TXT record announcing a
            // policy, and no policy of our own to serve. A policy served but
            // not yet announced - which is what 'mta-sts set' leaves behind -
            // still has our stored record, so it is still checked.
            var served = string.IsNullOrWhiteSpace(published.MtaStsRecord) && known is null
                ? ServedPolicy.Missing("Not checked: nothing announces a policy and none is configured here.")
                : await mtaSts.FetchAsync(domain, known?.Id ?? "", ct);

            // The records to publish, independent of whether anything can be
            // applied. A domain with neither a record nor a served policy is
            // skipped by the planner below - correctly, there is nothing safe
            // to change - and that is exactly the domain whose operator needs
            // to be told what to create.
            var policyHost = configuration["MtaSts:PolicyHost"];
            policyHostUnknown = string.IsNullOrWhiteSpace(policyHost);

            if (known is not null)
            {
                transportRecords = [.. TransportSetup.MtaSts(domain, policyHost, known)];
                policyFile = TransportSetup.PolicyFile(known);
            }
            else
            {
                // No policy has been created, so there is no id to announce
                // yet and inventing one would have somebody publish a version
                // number this product does not serve. Only the half that is
                // knowable is shown.
                transportRecords =
                [
                    .. TransportSetup.MtaSts(domain, policyHost, MtaStsPolicy.ForTesting([], DateTimeOffset.UtcNow))
                        .Where(r => r.Type == "CNAME"),
                ];
            }

            if (configuration["Reporting:TlsReportAddress"] is { Length: > 0 } tlsAddress
                && string.IsNullOrWhiteSpace(published.TlsRptRecord))
            {
                transportRecords = [.. transportRecords, TransportSetup.TlsReporting(domain, tlsAddress)];
            }
            if (!string.IsNullOrWhiteSpace(published.MtaStsRecord) || served.Reachable)
            {
                var mx = await lookup.MxAsync(domain, ct);

                var plan = TransportPlanner.MtaSts(domain, published.MtaStsRecord, served, mx);
                if (!plan.IsNoop) { plans.Add(plan); }
            }
        }

        string providerName;
        var canApply = false;
        string? providerError = null;
        try
        {
            var provider = await providers.ProviderForAsync(domain, ct);
            providerName = provider.Name;
            canApply = provider.CanWrite;
        }
        catch (InvalidOperationException ex)
        {
            // Configured but unusable: the secret is missing or unreadable.
            // Said on the page rather than hidden behind a disabled button.
            providerName = (await providers.ForDomainAsync(domain, ct))?.Provider ?? "manual";
            providerError = ex.Message;
        }

        // Anything the product can already offer to write is not also a record
        // to publish by hand. TLS-RPT was appearing twice - once as a plan with
        // an Apply button, once in the records table - which reads as two jobs.
        var planned = plans
            .Where(p => p.IsSafe && !p.IsNoop)
            .Select(p => (p.RecordName, p.RecordType))
            .ToHashSet();

        transportRecords = [.. transportRecords.Where(r => !planned.Contains((r.Name, r.Type)))];

        return new DomainFixes(domain, triage?.ClientName ?? "", published, triage, plans, providerName, canApply, providerError)
        {
            TransportRecords = transportRecords,
            PolicyFile = policyFile,
            PolicyHostUnknown = policyHostUnknown,
        };
    }

    public async Task<ApplyOutcome> ApplyAsync(ChangePlan plan, string by, string reason, CancellationToken ct = default)
    {
        var provider = await providers.ProviderForAsync(plan.Domain, ct);
        var outcome = await remediation.ApplyAsync(plan, provider, confirm: true, by, reason, ct);

        if (outcome.Applied && outcome.ChangeId is not null)
        {
            // A short wait, so the page can usually say "visible" rather
            // than "accepted". The record's old TTL can make it longer, and
            // the history table keeps showing the difference until it is.
            await remediation.VerifyAsync(outcome.ChangeId, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5), ct);
        }

        return outcome;
    }

    public async Task<ApplyOutcome> RollBackAsync(string changeId, string by, string reason, CancellationToken ct = default)
    {
        var change = await remediation.GetChangeAsync(changeId, ct)
            ?? throw new ArgumentException($"No change {changeId}.", nameof(changeId));
        var provider = await providers.ProviderForAsync(change.Domain, ct);
        return await remediation.RollBackAsync(change.Id, provider, by, reason, ct);
    }

    public Task<IReadOnlyList<AppliedChange>> HistoryAsync(string? tenantId, string? clientSlug = null, CancellationToken ct = default) =>
        remediation.HistoryAsync(null, 200, tenantId, clientSlug, ct);

    public Task<IReadOnlyList<DnsProviderConfig>> ProvidersAsync(string? tenantId, CancellationToken ct = default) =>
        providers.ListAsync(tenantId, ct);

    public Task<DnsProviderConfig> SetProviderAsync(
        string clientSlug, string? domain, string provider, IReadOnlyDictionary<string, string> settings, string? secret,
        CancellationToken ct = default) =>
        providers.SetAsync(clientSlug, domain, provider, settings, secret, ct);

    public Task<bool> RemoveProviderAsync(string clientSlug, string? domain, CancellationToken ct = default) =>
        providers.RemoveAsync(clientSlug, domain, ct);
}
