using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Rollout;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Fixes what 'dmarc check' finds, in the customer's DNS.
///
/// Dry run unless --apply is given, and every apply is recorded: who, when,
/// why, what was there before. That record is what the client's monthly
/// report prints under "what we did", so the reason given here is written
/// for the customer, not for the log.
/// </summary>
public static class FixCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        var store = new ReportStore(dbPath);
        if (!await store.IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        var lookup = new DnsLookup();
        var service = new RemediationService(dbPath);   // its own uncached resolver, for verifying
        var configs = new DnsProviderConfigs(dbPath, new LocalSecretStore());
        var by = Args.Value(args, "--by") ?? Environment.UserName;

        if (Args.Flag(args, "--history"))
        {
            return await HistoryAsync(service, Args.Value(args, "--domain"), ct).ConfigureAwait(false);
        }

        if (Args.Value(args, "--rollback") is { } changeId)
        {
            return await RollBackAsync(service, configs, changeId, by, Args.Value(args, "--reason"), ct).ConfigureAwait(false);
        }

        if (Args.Value(args, "--verify") is { } verifyId)
        {
            return await VerifyAsync(service, verifyId, ct).ConfigureAwait(false);
        }

        var domain = Args.Value(args, "--domain");
        var all = Args.Flag(args, "--all");
        var policy = Args.Value(args, "--policy");

        if (string.IsNullOrWhiteSpace(domain) && !all) { return Usage(); }

        if (all && policy is not null)
        {
            // Advancing every domain at once is not a fix, it is a rollout,
            // and each domain's reports say whether it is ready.
            Console.Error.WriteLine("--policy applies to one domain at a time. Name it with --domain.");
            return 64;
        }

        var domains = all
            ? (await new TriageService(dbPath).GetAsync(ct: ct).ConfigureAwait(false)).Select(t => t.Domain).ToList()
            : [domain!.Trim().ToLowerInvariant()];

        var apply = Args.Flag(args, "--apply");
        var reason = Args.Value(args, "--reason") ?? "";
        if (apply && reason.Length == 0)
        {
            Console.Error.WriteLine("--apply needs --reason \"...\": one sentence, written for the customer. It goes on their report.");
            return 64;
        }

        var worst = 0;
        foreach (var d in domains)
        {
            ct.ThrowIfCancellationRequested();
            worst = Math.Max(worst, await FixDomainAsync(d, args, policy, apply, by, reason, lookup, service, configs, dbPath, ct).ConfigureAwait(false));
        }

        Console.WriteLine();
        return worst;
    }

    private static async Task<int> FixDomainAsync(
        string domain, string[] args, string? policy, bool apply, string by, string reason,
        DnsLookup lookup, RemediationService service, DnsProviderConfigs configs, string dbPath, CancellationToken ct)
    {
        Console.WriteLine();
        Console.WriteLine($"  {domain}");

        var published = await lookup.ReadAsync(domain, ct).ConfigureAwait(false);
        if (published.LookupFailed)
        {
            // Nothing is planned from a failed read. "No record" and "could
            // not read" would plan opposite things.
            Console.WriteLine("    could not read DNS; nothing planned");
            return 1;
        }

        var plans = new List<ChangePlan>();
        var explicitOnly = policy is not null || Args.Flag(args, "--sp") || Args.Flag(args, "--dead-includes");

        if (policy is not null)
        {
            plans.Add(DmarcPolicyPlanner.Advance(domain, published.DmarcRecord, policy, Args.Int(args, "--pct", 100)));
        }

        // Without a specific ask, everything that is safe to do on the
        // record's own evidence: a weaker sp, an include that resolves to
        // nothing. Never a policy advance, which the reports have to justify.
        if (!explicitOnly || Args.Flag(args, "--sp"))
        {
            var sp = DmarcPolicyPlanner.FixSubdomainPolicy(domain, published.DmarcRecord);
            if (!sp.IsNoop || Args.Flag(args, "--sp")) { plans.Add(sp); }
        }

        if (!explicitOnly || Args.Flag(args, "--dead-includes"))
        {
            var spf = published.SpfRecords.Count > 0 ? published.SpfRecords[0] : null;
            plans.AddRange(published.DeadIncludes.Select(dead => SpfIncludePlanner.RemoveDeadInclude(domain, spf, dead)));
        }

        if (policy is null)
        {
            await SuggestPolicyAsync(domain, published, dbPath, ct).ConfigureAwait(false);
        }

        if (plans.Count == 0)
        {
            Console.WriteLine("    nothing to fix");
            return 0;
        }

        var provider = await configs.ProviderForAsync(domain, ct).ConfigureAwait(false);
        var worst = 0;

        foreach (var plan in plans)
        {
            var outcome = await service.ApplyAsync(plan, provider, apply, by, reason, ct).ConfigureAwait(false);
            Print(plan, outcome);

            if (outcome.Applied && outcome.ChangeId is not null && !Args.Flag(args, "--no-verify"))
            {
                Console.Write("    waiting for DNS to serve it");
                var seen = await service.VerifyAsync(outcome.ChangeId, TimeSpan.FromSeconds(90), TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                Console.WriteLine(seen ? " - visible" : $" - not yet. Check later: dmarc fix --verify {outcome.ChangeId[..8]}");
            }

            if (!plan.IsSafe) { worst = Math.Max(worst, 1); }
            if (apply && !outcome.Applied && outcome.Error.Length > 0 && plan.IsSafe && !plan.IsNoop) { worst = Math.Max(worst, 1); }
        }

        return worst;
    }

    /// <summary>
    /// Says when the reports say a domain is ready to advance, so the
    /// decision is made with the evidence in front of whoever makes it.
    /// </summary>
    private static async Task SuggestPolicyAsync(string domain, PublishedRecords published, string dbPath, CancellationToken ct)
    {
        var row = (await new TriageService(dbPath).GetAsync(ct: ct).ConfigureAwait(false))
            .FirstOrDefault(t => t.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
        if (row is null) { return; }

        var record = DmarcRecord.Parse(published.DmarcRecord);
        var live = record.IsValid ? record.Policy.ToLowerInvariant() : "";

        var next = row.Headline.Contains("Ready to move to p=", StringComparison.Ordinal)
            ? row.Headline[(row.Headline.IndexOf("p=", StringComparison.Ordinal) + 2)..].TrimEnd('.')
            : null;

        if (next is not null && live != next)
        {
            Console.WriteLine($"    the reports say: {row.Headline}");
            Console.WriteLine($"    to do it:        dmarc fix --domain {domain} --policy {next} --apply --reason \"...\"");
        }
        else if (row.Level >= TriageLevel.Watch && !row.Headline.Contains("Ready", StringComparison.Ordinal))
        {
            Console.WriteLine($"    the reports say: {row.Headline}");
        }
    }

    private static void Print(ChangePlan plan, ApplyOutcome outcome)
    {
        if (!plan.IsSafe)
        {
            // The summary of a refused plan is its first blocker; the rest
            // follow, once each.
            Console.WriteLine($"    [REFUSED] {plan.Blockers[0]}");
            foreach (var b in plan.Blockers.Skip(1)) { Console.WriteLine($"             also: {b}"); }
            return;
        }

        var label = plan.IsNoop ? "ok" : outcome.Applied ? "APPLIED" : "would";
        Console.WriteLine($"    [{label}] {plan.Summary}");

        if (!plan.IsNoop && plan.IsSafe)
        {
            Console.WriteLine($"             {plan.RecordName} {plan.RecordType}");
            Console.WriteLine($"             before: {(string.IsNullOrEmpty(outcome.Snapshot ?? plan.CurrentValue) ? "(nothing)" : outcome.Snapshot ?? plan.CurrentValue)}");
            Console.WriteLine($"             after:  {plan.ProposedValue}");
        }

        foreach (var w in plan.Warnings) { Console.WriteLine($"             note: {w}"); }

        if (outcome.Error.Length > 0) { Console.WriteLine($"             {outcome.Message}"); }
        else if (outcome.DryRun && !plan.IsNoop) { Console.WriteLine($"             dry run via {outcome.Provider}. Add --apply --reason \"...\" to write it."); }
    }

    private static async Task<int> HistoryAsync(RemediationService service, string? domain, CancellationToken ct)
    {
        var history = await service.HistoryAsync(domain, ct: ct).ConfigureAwait(false);
        if (history.Count == 0)
        {
            Console.WriteLine(domain is null ? "No changes have been applied yet." : $"No changes have been applied to {domain}.");
            return 0;
        }

        Console.WriteLine();
        foreach (var c in history)
        {
            var state = c.RolledBackAt is not null ? "rolled back" : c.IsPropagated ? "live" : "applied, not yet seen in DNS";
            Console.WriteLine($"  {c.Id[..8]}  {c.AppliedAt:yyyy-MM-dd HH:mm}  {c.Domain,-24} {c.RecordName,-32} {state}");
            Console.WriteLine($"            before: {c.PreviousValue ?? "(nothing)"}");
            Console.WriteLine($"            after:  {c.NewValue ?? "(removed)"}");
            Console.WriteLine($"            by {c.AppliedBy ?? "?"} via {c.Provider}: {c.Reason}");
            if (c.RolledBackAt is not null) { Console.WriteLine($"            rolled back {c.RolledBackAt:yyyy-MM-dd HH:mm}: {c.RollbackReason}"); }
            Console.WriteLine();
        }
        return 0;
    }

    private static async Task<int> RollBackAsync(
        RemediationService service, DnsProviderConfigs configs, string changeId, string by, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            Console.Error.WriteLine("--rollback needs --reason \"...\". It goes on the customer's report beside the change it undoes.");
            return 64;
        }

        var change = await service.GetChangeAsync(changeId, ct).ConfigureAwait(false);
        if (change is null)
        {
            Console.Error.WriteLine($"No change {changeId}. See: dmarc fix --history");
            return 66;
        }

        var provider = await configs.ProviderForAsync(change.Domain, ct).ConfigureAwait(false);
        var outcome = await service.RollBackAsync(change.Id, provider, by, reason, ct).ConfigureAwait(false);
        Console.WriteLine(outcome.Message);
        return outcome.Applied ? 0 : 1;
    }

    private static async Task<int> VerifyAsync(RemediationService service, string changeId, CancellationToken ct)
    {
        var change = await service.GetChangeAsync(changeId, ct).ConfigureAwait(false);
        if (change is null)
        {
            Console.Error.WriteLine($"No change {changeId}. See: dmarc fix --history");
            return 66;
        }

        var seen = await service.VerifyAsync(change.Id, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        Console.WriteLine(seen
            ? $"{change.RecordName} now serves the new value."
            : $"{change.RecordName} does not serve the new value yet. Propagation can take up to the record's old TTL.");
        return seen ? 0 : 1;
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            dmarc fix --domain <domain> [--apply --reason "..."]     plan (or apply) the safe fixes for one domain
            dmarc fix --all [--apply --reason "..."]                 the same for every domain
            dmarc fix --domain <domain> --policy quarantine|reject [--pct <n>]
            dmarc fix --domain <domain> --sp                         only the subdomain policy
            dmarc fix --domain <domain> --dead-includes              only includes that resolve to nothing
            dmarc fix --history [--domain <domain>]
            dmarc fix --verify <change id>
            dmarc fix --rollback <change id> --reason "..."
            """);
        return 64;
    }
}
