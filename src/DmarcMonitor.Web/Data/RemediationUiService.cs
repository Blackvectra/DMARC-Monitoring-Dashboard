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
    DnsProviderConfigs providers)
{
    private readonly TriageService _triage = new(database.Path);

    public string SecretsDescription => providers.Secrets.Description;
    public bool SecretsAvailable => providers.Secrets.IsAvailable;

    /// <summary>Every domain, with the safe fixes planned. Reads DNS for each, so it is slow.</summary>
    public async Task<IReadOnlyList<DomainFixes>> PlanAllAsync(CancellationToken ct = default)
    {
        var rows = await _triage.GetAsync(ct: ct);
        var result = new List<DomainFixes>();

        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            result.Add(await PlanAsync(row.Domain, row, null, ct));
        }

        return result;
    }

    /// <summary>
    /// One domain, with the safe fixes and optionally a policy move planned.
    /// </summary>
    public async Task<DomainFixes> PlanAsync(string domain, DomainTriage? triage, string? policy, CancellationToken ct = default)
    {
        triage ??= (await _triage.GetAsync(ct: ct)).FirstOrDefault(t => t.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
        var published = await lookup.ReadAsync(domain, ct);
        var plans = new List<ChangePlan>();

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

        return new DomainFixes(domain, triage?.ClientName ?? "", published, triage, plans, providerName, canApply, providerError);
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

    public Task<IReadOnlyList<AppliedChange>> HistoryAsync(CancellationToken ct = default) =>
        remediation.HistoryAsync(null, 200, ct);

    public Task<IReadOnlyList<DnsProviderConfig>> ProvidersAsync(CancellationToken ct = default) =>
        providers.ListAsync(ct);

    public Task<DnsProviderConfig> SetProviderAsync(
        string clientSlug, string? domain, string provider, IReadOnlyDictionary<string, string> settings, string? secret,
        CancellationToken ct = default) =>
        providers.SetAsync(clientSlug, domain, provider, settings, secret, ct);

    public Task<bool> RemoveProviderAsync(string clientSlug, string? domain, CancellationToken ct = default) =>
        providers.RemoveAsync(clientSlug, domain, ct);
}
