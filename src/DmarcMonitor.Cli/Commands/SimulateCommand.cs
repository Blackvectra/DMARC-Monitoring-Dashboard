using DmarcMonitor.Core.Rollout;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Replays the reports already held against a record nobody has published.
///
/// Every tag change was otherwise a guess. The question an operator actually
/// asks - "what would moving this domain to quarantine have done to the mail I
/// already have reports for" - is answerable from aggregate_records and took
/// hand-written SQL to answer.
/// </summary>
public static class SimulateCommand
{
    private const int DefaultWindowDays = 30;

    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--domain", "--policy", "--adkim", "--aspf", "--pct", "--days")
            is var bad and not 0)
        {
            return bad;
        }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var domain = Args.Value(args, "--domain");
        var days = Args.Int(args, "--days", DefaultWindowDays);

        if (string.IsNullOrWhiteSpace(domain))
        {
            Console.Error.WriteLine("dmarc simulate --domain <domain> [--policy none|quarantine|reject]");
            Console.Error.WriteLine("                               [--adkim r|s] [--aspf r|s] [--pct <n>]");
            Console.Error.WriteLine("                               [--days <n>] [--db <path>]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Anything not given keeps whatever the domain publishes today, so");
            Console.Error.WriteLine("  the answer is the cost of the change rather than of the whole record.");
            return 64;
        }

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}. This replays reports, so it needs them.");
            return 66;
        }

        var service = new PolicySimulationService(dbPath);
        var current = await service.CurrentAsync(domain, days, ct).ConfigureAwait(false);
        var rows = await service.RowsAsync(domain, days, ct).ConfigureAwait(false);

        if (rows.Count == 0)
        {
            Console.Error.WriteLine($"No reports held for {domain} in the last {days} days, so there is "
                                  + "nothing to replay. Widen the window with --days, or check the domain name.");
            return 66;
        }

        // Anything not asked about keeps what the domain publishes today. A
        // simulation against a record the operator did not propose would
        // answer a question nobody asked.
        var proposal = new ProposedPolicy
        {
            StrictDkim = Strict(args, "--adkim", current?.StrictDkim ?? false),
            StrictSpf = Strict(args, "--aspf", current?.StrictSpf ?? false),
            Policy = (Args.Value(args, "--policy") ?? current?.Policy ?? "none").Trim().ToLowerInvariant(),
            Percent = Args.Int(args, "--pct", current?.Percent ?? 100),
        };

        if (proposal.Policy is not ("none" or "quarantine" or "reject"))
        {
            Console.Error.WriteLine($"--policy takes none, quarantine or reject, not '{proposal.Policy}'.");
            return 64;
        }

        // The baseline is the record in force over this mail, not what the
        // receivers concluded. Measured the other way, changing p= alone -
        // which cannot alter whether anything passes - reports a cost.
        var inForce = new ProposedPolicy
        {
            StrictDkim = current?.StrictDkim ?? false,
            StrictSpf = current?.StrictSpf ?? false,
            Policy = current?.Policy ?? "none",
            Percent = current?.Percent ?? 100,
        };

        var outcome = PolicySimulator.Run(rows, inForce, proposal);

        Console.WriteLine();
        Console.WriteLine($"  {domain}");
        Console.WriteLine($"    {Evidence(outcome, current, days)}");
        Console.WriteLine($"    now      {Describe(current)}");
        Console.WriteLine($"    proposed {Describe(proposal)}");
        Console.WriteLine();

        foreach (var line in Verdict(outcome, proposal)) { Console.WriteLine($"    {line}"); }

        if (outcome.Sources.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("    who is behind it");
            foreach (var s in outcome.Sources.Take(10))
            {
                var what = s.NewlyFailing > 0
                    ? $"{s.NewlyFailing,7:N0} would start failing"
                    : $"{s.NewlyPassing,7:N0} would start passing";

                var how = s.Signs.Length > 0 ? $"signs {s.Signs}"
                        : s.Envelope.Length > 0 ? $"envelope {s.Envelope}"
                        : "no authentication at all";

                Console.WriteLine($"      {s.SourceIp,-40} {what}   {how}");
            }

            if (outcome.Sources.Count > 10)
            {
                Console.WriteLine($"      and {outcome.Sources.Count - 10} more");
            }
        }

        Console.WriteLine();

        // Non-zero when the change costs mail, so this can gate a script that
        // would otherwise publish it.
        return outcome.NewlyFailing > 0 ? 1 : 0;
    }

    /// <summary>
    /// How much history this rests on.
    /// </summary>
    /// <remarks>
    /// First, and its own line, because it decides what the rest is worth. Six
    /// days of reports over a thirty-day window is a real and common state -
    /// receivers go quiet, a collector is not running yet - and a confident
    /// answer drawn from it should be read as what it is.
    /// </remarks>
    internal static string Evidence(SimulationOutcome outcome, CurrentPolicy? current, int windowDays)
    {
        ArgumentNullException.ThrowIfNull(outcome);

        var held = current is { WindowDays: > 0 } ? current.WindowDays : windowDays;

        var text = $"{outcome.Messages:N0} message(s) across {held} day(s) of reports, "
                 + $"asked for the last {windowDays}";

        // Said here rather than buried, because it bounds everything below. A
        // message whose row cannot account for the receiver's verdict is one
        // this cannot model, and pretending otherwise is how a simulator
        // invents a cost.
        return outcome.Unexplained == 0
            ? text
            : $"{text}; {outcome.Unexplained:N0} of them carried a signature the store did not keep, "
              + "so they are left out of every figure below";
    }

    internal static string Describe(CurrentPolicy? current) =>
        current is null
            ? "nothing published that the reports have seen"
            : Describe(new ProposedPolicy
            {
                Policy = current.Policy,
                StrictDkim = current.StrictDkim,
                StrictSpf = current.StrictSpf,
                Percent = current.Percent,
            });

    internal static string Describe(ProposedPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var text = $"p={policy.Policy}; adkim={(policy.StrictDkim ? "s" : "r")}; "
                 + $"aspf={(policy.StrictSpf ? "s" : "r")}";

        return policy.Percent < 100 ? $"{text}; pct={policy.Percent}" : text;
    }

    /// <summary>
    /// The answer, in the order somebody reads it: what it costs, what it
    /// recovers, what then happens to the failures.
    /// </summary>
    /// <remarks>
    /// "It costs nothing" is stated as plainly as a warning would be. That is
    /// the answer that unblocks somebody, and a tool that only ever warns is
    /// one an operator learns to route around.
    /// </remarks>
    internal static IReadOnlyList<string> Verdict(SimulationOutcome outcome, ProposedPolicy proposal)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(proposal);

        var lines = new List<string>
        {
            outcome.NewlyFailing == 0
                ? "costs nothing: no message in the reports held would stop passing"
                : $"COSTS {outcome.NewlyFailing:N0} message(s) that pass today and would not",
        };

        if (outcome.NewlyPassing > 0)
        {
            lines.Add($"recovers {outcome.NewlyPassing:N0} message(s) that fail today and would pass");
        }

        var failing = outcome.FailingAfter;

        lines.Add(proposal.Policy switch
        {
            "reject" when outcome.WouldBeActedOn > 0 =>
                $"at p=reject {outcome.WouldBeActedOn:N0} of the {failing:N0} failing message(s) would be "
                + "refused outright"
                + (outcome.WouldBeDeliveredAnyway > 0
                    ? $", and pct={proposal.Percent} would deliver the other {outcome.WouldBeDeliveredAnyway:N0}"
                    : ""),
            "quarantine" when outcome.WouldBeActedOn > 0 =>
                $"at p=quarantine {outcome.WouldBeActedOn:N0} of the {failing:N0} failing message(s) would "
                + "go to junk"
                + (outcome.WouldBeDeliveredAnyway > 0
                    ? $", and pct={proposal.Percent} would deliver the other {outcome.WouldBeDeliveredAnyway:N0}"
                    : ""),
            "none" =>
                $"at p=none nothing is blocked: the {failing:N0} failing message(s) are delivered and "
                + "reported",
            _ => $"nothing fails under this record, so the policy has nothing to act on",
        });

        // The SPF question, which is asked as often as the policy one and is
        // not answered by either number above.
        if (outcome.PassingAfter > 0)
        {
            lines.Add($"of the {outcome.PassingAfter:N0} that pass: {outcome.PassingOnDkimOnly:N0} on DKIM "
                    + $"alone, {outcome.PassingOnSpfOnly:N0} on SPF alone, {outcome.PassingOnBoth:N0} on "
                    + "both. Tightening the SPF all-mechanism can only touch the SPF-alone ones.");
        }

        return lines;
    }

    private static bool Strict(string[] args, string flag, bool fallback)
    {
        var value = Args.Value(args, flag);
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : value.Trim().StartsWith('s');
    }
}
