using System.Globalization;
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
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--domain", "--policy", "--pct", "--sp", "--reason", "--by", "--rollback", "--verify", "--tls-rpt-to", "--transport", "!--all", "!--apply", "!--history", "!--dead-includes", "!--no-verify") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        var store = new ReportStore(dbPath);
        if (!await store.IsInitializedAsync(ct).ConfigureAwait(false))
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

        // Checked here rather than left to Args.Int, whose silent fallback is
        // the wrong shape for a safety limit. It returns 100 for anything that
        // is not a positive integer, so "--pct twentyfive", "--pct 0",
        // "--pct -5" and a value accidentally split by a space all planned the
        // change at 100% of failing mail - the opposite of what somebody
        // typing --pct wants, with nothing printed to say the flag was
        // dropped. Above 100 it threw instead, and the stack trace reached the
        // operator under a banner saying "This is a bug".
        var percent = 100;
        if (Args.Value(args, "--pct") is { } pctText)
        {
            if (!int.TryParse(pctText, NumberStyles.Integer, CultureInfo.InvariantCulture, out percent)
                || percent is < 1 or > 100)
            {
                Console.Error.WriteLine($"--pct takes a whole number from 1 to 100. '{pctText}' is not one.");
                return 64;
            }
        }

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
            worst = Math.Max(worst, await FixDomainAsync(d, args, policy, percent, apply, by, reason, lookup, service, configs, dbPath, ct).ConfigureAwait(false));
        }

        Console.WriteLine();
        return worst;
    }

    private static async Task<int> FixDomainAsync(
        string domain, string[] args, string? policy, int percent, bool apply, string by, string reason,
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
        var explicitOnly = policy is not null || Args.Flag(args, "--sp") || Args.Flag(args, "--dead-includes")
                        || Args.Flag(args, "--transport");

        if (policy is not null)
        {
            plans.Add(DmarcPolicyPlanner.Advance(domain, published.DmarcRecord, policy, percent));
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

        // Transport security: TLS-RPT asks for reports and changes nothing
        // about delivery, so it is planned freely. MTA-STS is only ever
        // announced for a policy that is already being served, which the
        // planner checks by fetching it.
        if (!explicitOnly || Args.Flag(args, "--transport"))
        {
            plans.AddRange(await TransportAsync(domain, published, args, dbPath, ct).ConfigureAwait(false));
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
    /// The transport-security plans for a domain: TLS-RPT, then MTA-STS.
    /// </summary>
    /// <remarks>
    /// TLS-RPT first and always, because it is what produces the evidence the
    /// MTA-STS decision needs. Enforcing transport security without reports is
    /// enforcement with the lights off.
    /// </remarks>
    private static async Task<List<ChangePlan>> TransportAsync(
        string domain, PublishedRecords published, string[] args, string dbPath, CancellationToken ct)
    {
        var plans = new List<ChangePlan>();

        if (Args.Value(args, "--tls-rpt-to") is { Length: > 0 } address)
        {
            var tls = TransportPlanner.TlsReporting(domain, published.TlsRptRecord, address);
            if (!tls.IsNoop) { plans.Add(tls); }
        }
        else if (string.IsNullOrWhiteSpace(published.TlsRptRecord))
        {
            Console.WriteLine("    no TLS-RPT record, so nobody reports failed or downgraded connections.");
            Console.WriteLine($"    to publish one: dmarc fix --domain {domain} --tls-rpt-to <address> --apply --reason \"...\"");
        }

        // Fetched rather than assumed: the record says a policy exists, only
        // the file says what it is, and a sender reads the file.
        //
        // The id, though, is not in the file - RFC 8461 keeps it in the TXT
        // record alone - so it has to come from this product's own record of
        // the policy. Fetching without it built "v=STSv1; id=", which no
        // sender accepts.
        var known = await new MtaStsStore(dbPath).GetAsync(domain, ct).ConfigureAwait(false);
        var served = await new MtaStsFetcher().FetchAsync(domain, known?.Id ?? "", ct).ConfigureAwait(false);
        if (!served.Reachable && string.IsNullOrWhiteSpace(published.MtaStsRecord))
        {
            // Nothing published and nothing served is not a fault to plan
            // around, it is a domain nobody has set this up for.
            Console.WriteLine($"    no MTA-STS policy. To start one: dmarc mta-sts set --domain {domain}");
            return plans;
        }

        var mx = await new DnsLookup().MxAsync(domain, ct).ConfigureAwait(false);
        var mtaSts = TransportPlanner.MtaSts(domain, published.MtaStsRecord, served, mx);
        if (!mtaSts.IsNoop) { plans.Add(mtaSts); }

        return plans;
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

        // Taken from after "Ready to move to p=", not after the first "p=".
        // The headline reads "p=none with everything authenticating. Ready to
        // move to p=reject.", so the first "p=" is the CURRENT policy, and the
        // suggested command came out as
        //
        //   dmarc fix --domain x --policy none with everything authenticating. Ready to move to p=reject --apply
        //
        // which a shell splits into stray words, binding --policy to "none" -
        // the policy the domain is already on. Pasting the product's own
        // instruction answered "[ok] x is already at p=none" and exited 0, so
        // the operator was told the job was done while the domain stayed
        // unprotected. It fired on precisely the domains that were ready to
        // advance, which is the only case this code runs for.
        const string Marker = "Ready to move to p=";
        var at = row.Headline.IndexOf(Marker, StringComparison.Ordinal);
        var next = at < 0 ? null : row.Headline[(at + Marker.Length)..].TrimEnd('.').Trim();

        // And checked, rather than printed on trust. A headline that changes
        // shape should stop the suggestion, not emit a command that means
        // something else.
        if (next is not null && next is not ("none" or "quarantine" or "reject")) { next = null; }

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
