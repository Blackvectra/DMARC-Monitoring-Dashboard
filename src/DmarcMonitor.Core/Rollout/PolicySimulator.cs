using DmarcMonitor.Core.Domains;

namespace DmarcMonitor.Core.Rollout;

/// <summary>
/// One stored report row, reduced to the facts DMARC actually evaluates.
/// </summary>
/// <remarks>
/// The result travels with the domain on both mechanisms, and that pairing is
/// the whole point. A forger signing as its victim produces
/// <c>domain=victim.com, result=fail</c>, which is indistinguishable from the
/// victim's own service if only the domain is kept - and a simulator that read
/// the domain alone would report that relaxing alignment recovers the forgery.
/// </remarks>
public sealed record AuthenticationFacts
{
    /// <summary>The domain in the From header: what DMARC aligns against.</summary>
    public required string HeaderFrom { get; init; }

    /// <summary>The <c>d=</c> domain of the signature the report carried, if any.</summary>
    public string? DkimDomain { get; init; }

    /// <summary>True when that signature actually verified.</summary>
    public bool DkimPassed { get; init; }

    /// <summary>The domain SPF was checked against, if any.</summary>
    public string? SpfDomain { get; init; }

    /// <summary>True when that check actually passed.</summary>
    public bool SpfPassed { get; init; }

    public long Messages { get; init; }

    public string SourceIp { get; init; } = "";

    /// <summary>
    /// What the receiver concluded at the time, under the policy then in force.
    /// </summary>
    /// <remarks>
    /// Kept as ground truth rather than recomputed. A report row is one
    /// signature and one SPF check out of however many the message carried, so
    /// re-deriving the verdict from it can disagree with what the receiver
    /// actually did - and the receiver is right. Every figure below is a delta
    /// against this rather than a replacement for it.
    /// </remarks>
    public bool PassedAsEvaluated { get; init; }
}

/// <summary>A record an operator is thinking about publishing.</summary>
public sealed record ProposedPolicy
{
    /// <summary><c>adkim=s</c>.</summary>
    public bool StrictDkim { get; init; }

    /// <summary><c>aspf=s</c>.</summary>
    public bool StrictSpf { get; init; }

    /// <summary>none, quarantine or reject.</summary>
    public string Policy { get; init; } = "none";

    public int Percent { get; init; } = 100;
}

/// <summary>What one source would do differently under a proposed record.</summary>
public sealed record SourceImpact
{
    public required string SourceIp { get; init; }
    public long NewlyFailing { get; init; }
    public long NewlyPassing { get; init; }
    public string Signs { get; init; } = "";
    public string Envelope { get; init; } = "";
}

/// <summary>What replaying the stored reports against a proposal produced.</summary>
public sealed record SimulationOutcome
{
    public long Messages { get; init; }

    /// <summary>Messages the receivers passed, under the record in force at the time.</summary>
    public long PassingNow { get; init; }

    /// <summary>
    /// Messages whose stored row cannot account for what the receiver decided.
    /// </summary>
    /// <remarks>
    /// A message can carry several DKIM signatures and the store keeps one of
    /// them - the first that verified. Where a receiver passed a message on a
    /// signature that is not the one kept, replaying the row reaches the
    /// opposite verdict, and any delta computed from it would be invented.
    ///
    /// So these are counted, excluded from every figure below, and reported.
    /// On a real domain it was nine messages out of 929, all of them Microsoft
    /// 365 mail carrying a tenant signature alongside the customer's own.
    /// </remarks>
    public long Unexplained { get; init; }

    /// <summary>Messages this can actually model: everything but <see cref="Unexplained"/>.</summary>
    public long Modelled => Messages - Unexplained;

    /// <summary>Of the modelled messages, how many pass under the current record.</summary>
    public long PassingBefore { get; init; }

    /// <summary>Of the modelled messages, how many pass under the proposal.</summary>
    public long PassingAfter { get; init; }

    /// <summary>Passing under the current record, failing under the proposal. The cost.</summary>
    public long NewlyFailing { get; init; }

    /// <summary>Failing under the current record, passing under the proposal. The recovery.</summary>
    public long NewlyPassing { get; init; }

    /// <summary>
    /// Passing messages that rest on DKIM alone, so the SPF all-mechanism does
    /// not touch them.
    /// </summary>
    public long PassingOnDkimOnly { get; init; }

    /// <summary>Passing messages that rest on SPF alone. Tightening SPF puts these at risk.</summary>
    public long PassingOnSpfOnly { get; init; }

    /// <summary>Passing messages that would survive either mechanism failing.</summary>
    public long PassingOnBoth { get; init; }

    /// <summary>Modelled messages that fail under the proposal.</summary>
    public long FailingAfter => Modelled - PassingAfter;

    /// <summary>Failing messages the proposed policy would act on.</summary>
    public long WouldBeActedOn { get; init; }

    /// <summary>Failing messages the proposed pct would let through regardless.</summary>
    public long WouldBeDeliveredAnyway { get; init; }

    public IReadOnlyList<SourceImpact> Sources { get; init; } = [];

    /// <summary>True when the proposal changes nothing about what passes.</summary>
    public bool CostsNothing => NewlyFailing == 0;
}

/// <summary>
/// Replays the reports already held against a record nobody has published yet.
///
/// Every DMARC tag change is otherwise a guess. The data to answer "what would
/// this have done to the mail I already have reports for" is sitting in
/// aggregate_records, and producing the answer by hand takes SQL an operator
/// cannot be expected to write.
///
/// The care this needs is in one rule, and getting it wrong produces confident
/// nonsense: <b>alignment only matters when the underlying mechanism
/// authenticated.</b> Answering a real question about a real domain by hand, I
/// matched the SPF and DKIM domains against the From domain by shape, found
/// seventeen that looked as though relaxed alignment would rescue them, and
/// said so. All seventeen had already aligned strictly and failed because SPF
/// or DKIM had failed outright, so the true answer was zero. A simulator that
/// repeats that is worse than none, because it reads as authoritative.
///
/// The second rule is the baseline. A change is measured from the record in
/// force, not from what the receivers concluded - otherwise changing p= alone,
/// which cannot alter whether anything passes, reports a cost. It did, on the
/// first run against real data: nine messages, every one of them a row that
/// could not explain the receiver's verdict rather than anything the change
/// would do.
/// </summary>
public static class PolicySimulator
{
    /// <summary>
    /// Whether DMARC would pass for one row under the proposed alignment.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §4.2: a pass needs one of the two mechanisms to have
    /// authenticated AND its domain to align. Both halves, on the same
    /// mechanism. The authentication test comes first here deliberately - it
    /// is the one that was skipped by hand.
    /// </remarks>
    public static bool WouldPass(AuthenticationFacts row, bool strictDkim, bool strictSpf)
    {
        ArgumentNullException.ThrowIfNull(row);
        return DkimCounts(row, strictDkim) || SpfCounts(row, strictSpf);
    }

    private static bool DkimCounts(AuthenticationFacts row, bool strict) =>
        row.DkimPassed
        && !string.IsNullOrWhiteSpace(row.DkimDomain)
        && Alignment.Aligns(row.DkimDomain!, row.HeaderFrom, strict);

    private static bool SpfCounts(AuthenticationFacts row, bool strict) =>
        row.SpfPassed
        && !string.IsNullOrWhiteSpace(row.SpfDomain)
        && Alignment.Aligns(row.SpfDomain!, row.HeaderFrom, strict);

    /// <summary>
    /// Replays every row: what the record in force does with it, against what
    /// the proposal would.
    /// </summary>
    /// <param name="rows">The stored reports.</param>
    /// <param name="current">The record in force over the mail being replayed.</param>
    /// <param name="proposal">The record being considered.</param>
    public static SimulationOutcome Run(
        IReadOnlyList<AuthenticationFacts> rows, ProposedPolicy current, ProposedPolicy proposal)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(proposal);

        long messages = 0, passingNow = 0, unexplained = 0;
        long passingBefore = 0, passingAfter = 0, newlyFailing = 0, newlyPassing = 0;
        long dkimOnly = 0, spfOnly = 0, both = 0;

        var bySource = new Dictionary<string, (long Fail, long Pass, string Signs, string Envelope)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows)
        {
            messages += row.Messages;
            if (row.PassedAsEvaluated) { passingNow += row.Messages; }

            var before = WouldPass(row, current.StrictDkim, current.StrictSpf);

            // The row cannot account for what the receiver decided, so it
            // cannot be trusted to say what a change would do to it either.
            if (before != row.PassedAsEvaluated)
            {
                unexplained += row.Messages;
                continue;
            }

            var after = WouldPass(row, proposal.StrictDkim, proposal.StrictSpf);

            if (before) { passingBefore += row.Messages; }
            if (after) { passingAfter += row.Messages; }

            // Which mechanism carries the pass under the proposal. This is what
            // answers "does tightening SPF to -all cost anything": a message
            // resting on DKIM does not care what the all-mechanism says.
            if (after)
            {
                var dkim = DkimCounts(row, proposal.StrictDkim);
                var spf = SpfCounts(row, proposal.StrictSpf);

                if (dkim && spf) { both += row.Messages; }
                else if (dkim) { dkimOnly += row.Messages; }
                else { spfOnly += row.Messages; }
            }

            if (before == after) { continue; }

            if (after) { newlyPassing += row.Messages; } else { newlyFailing += row.Messages; }

            var key = row.SourceIp;

            // Spelled out rather than relying on the tuple's default, whose
            // string members are null rather than empty.
            if (!bySource.TryGetValue(key, out var impact)) { impact = (0, 0, "", ""); }

            bySource[key] = after
                ? (impact.Fail, impact.Pass + row.Messages, Pick(impact.Signs, row.DkimDomain), Pick(impact.Envelope, row.SpfDomain))
                : (impact.Fail + row.Messages, impact.Pass, Pick(impact.Signs, row.DkimDomain), Pick(impact.Envelope, row.SpfDomain));
        }

        // What the policy would then do to the mail that fails. Separate from
        // the pass/fail question above: p= changes nothing about what passes,
        // only what becomes of what does not.
        var failingAfter = messages - unexplained - passingAfter;
        var actedOn = proposal.Policy is "quarantine" or "reject"
            ? failingAfter * Math.Clamp(proposal.Percent, 0, 100) / 100
            : 0;

        return new SimulationOutcome
        {
            Messages = messages,
            PassingNow = passingNow,
            Unexplained = unexplained,
            PassingBefore = passingBefore,
            PassingAfter = passingAfter,
            NewlyFailing = newlyFailing,
            NewlyPassing = newlyPassing,
            PassingOnDkimOnly = dkimOnly,
            PassingOnSpfOnly = spfOnly,
            PassingOnBoth = both,
            WouldBeActedOn = actedOn,
            WouldBeDeliveredAnyway = failingAfter - actedOn,
            Sources =
            [
                .. bySource
                    .Select(kv => new SourceImpact
                    {
                        SourceIp = kv.Key,
                        NewlyFailing = kv.Value.Fail,
                        NewlyPassing = kv.Value.Pass,
                        Signs = kv.Value.Signs,
                        Envelope = kv.Value.Envelope,
                    })
                    .OrderByDescending(s => s.NewlyFailing)
                    .ThenByDescending(s => s.NewlyPassing),
            ],
        };
    }

    private static string Pick(string existing, string? candidate) =>
        existing.Length > 0 ? existing : (candidate ?? "").Trim();
}
