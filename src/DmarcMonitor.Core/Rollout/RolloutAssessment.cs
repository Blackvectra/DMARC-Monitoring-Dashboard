namespace DmarcMonitor.Core.Rollout;

/// <summary>How urgent a domain is. Ordering, not decoration.</summary>
public enum TriageLevel
{
    /// <summary>Nothing to do.</summary>
    Fine,

    /// <summary>
    /// Deliberately mid-rollout and on schedule.
    /// </summary>
    /// <remarks>
    /// Distinct from Fine so an operator can see the rollout is running, and
    /// distinct from Watch so it does not nag. A domain on day three of a
    /// planned two-week baseline is doing exactly what it should; reporting
    /// that as outstanding work is how a triage list becomes noise.
    /// </remarks>
    OnTrack,

    /// <summary>Worth knowing, not worth interrupting anyone.</summary>
    Watch,

    /// <summary>Mail will be lost at the next policy step, or something has stalled.</summary>
    Act,

    /// <summary>Mail is being lost right now.</summary>
    Urgent,
}

/// <summary>What is known about a domain at the moment of judging it.</summary>
public sealed record DomainState
{
    public required string Domain { get; init; }

    public string Policy { get; init; } = "none";
    public string PolicyTarget { get; init; } = "reject";

    public long Messages { get; init; }
    public long Passing { get; init; }
    public int FailingSources { get; init; }

    public DateTimeOffset? LastReport { get; init; }
    public DateTimeOffset? BaselineStarted { get; init; }
    public int BaselineDays { get; init; } = 14;

    /// <summary>Injected so the assessment is testable rather than dependent on the clock.</summary>
    public DateTimeOffset Now { get; init; } = DateTimeOffset.UtcNow;

    public long Failing => Messages - Passing;
    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);
    public bool IsEnforcing => Policy is "reject" or "quarantine";

    public int? DaysAtStage => BaselineStarted is null ? null : (int)(Now - BaselineStarted.Value).TotalDays;
    public bool InBaseline => DaysAtStage is { } d && d < BaselineDays;
}

public sealed record RolloutVerdict
{
    public required TriageLevel Level { get; init; }
    public required string Headline { get; init; }
}

/// <summary>
/// Decides what a domain needs, and says it in one sentence.
///
/// Pure, so it can be tested against every combination rather than eyeballed
/// on a page. The ordering is the design: the worst TRUE statement wins, and a
/// deliberate baseline outranks the states it would otherwise look like,
/// because it is the reason the domain appears unfinished.
/// </summary>
public static class RolloutAssessment
{
    /// <summary>
    /// A domain that has stopped reporting for this long has probably had its
    /// record changed or removed. Three days is past any normal gap: every
    /// major receiver reports at least daily.
    /// </summary>
    public const int SilentDays = 3;

    /// <summary>Below this, an enforcing domain is losing mail worth interrupting someone for.</summary>
    public const double HealthyPassRate = 95;

    public static RolloutVerdict Assess(DomainState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // Never reported at all. Usually the record was never published, or
        // was published without a rua address, and nothing else on a triage
        // page would reveal it.
        if (state.LastReport is null)
        {
            return new RolloutVerdict
            {
                Level = TriageLevel.Watch,
                Headline = "No reports yet. Check the DMARC record is published and includes a rua address.",
            };
        }

        // Reported once and then stopped. Checked before everything else
        // because stale data makes every other judgment below it wrong.
        var silentFor = state.Now - state.LastReport.Value;
        if (silentFor.TotalDays > SilentDays)
        {
            return new RolloutVerdict
            {
                Level = TriageLevel.Act,
                Headline = $"No reports for {(int)silentFor.TotalDays} days. Either the DMARC record changed, "
                         + "or collection stopped. Check both: one is the customer's DNS, the other is ours.",
            };
        }

        // Enforcing and losing mail. The only state worth interrupting
        // somebody for, so it outranks everything except stale data.
        if (state.IsEnforcing && state.PassRate < HealthyPassRate && state.Failing > 0)
        {
            var what = state.Policy == "reject" ? "refused" : "sent to junk";
            return new RolloutVerdict
            {
                Level = TriageLevel.Urgent,
                Headline = $"p={state.Policy} with {state.PassRate}% passing. {state.Failing:N0} message(s) were "
                         + $"{what} from {state.FailingSources} source(s).",
            };
        }

        // A deliberate baseline still running is the rollout working. This has
        // to come before the p=none branches, or every newly onboarded domain
        // is reported as needing work from the moment it is added, which is
        // exactly when it needs none.
        if (!state.IsEnforcing && state.InBaseline)
        {
            var remaining = state.BaselineDays - state.DaysAtStage!.Value;
            var found = state.Failing > 0
                ? $" {state.Failing:N0} message(s) are failing, which is what this window is for: find them now, fix them before enforcing."
                : " Nothing failing so far.";

            return new RolloutVerdict
            {
                Level = TriageLevel.OnTrack,
                Headline = $"Day {state.DaysAtStage} of a {state.BaselineDays}-day baseline at p=none. "
                         + $"{remaining} day(s) before moving to p={state.PolicyTarget}.{found}",
            };
        }

        // Baseline finished, or never set, with failures outstanding.
        if (!state.IsEnforcing && state.Failing > 0)
        {
            var overdue = state.DaysAtStage is { } d && d >= state.BaselineDays
                ? $"Baseline finished on day {state.BaselineDays} and it is now day {d}. "
                : "";

            return new RolloutVerdict
            {
                Level = state.PassRate < 90 ? TriageLevel.Act : TriageLevel.Watch,
                Headline = overdue
                         + $"p=none, {state.PassRate}% passing. Enforcing today would lose {state.Failing:N0} message(s) "
                         + $"from {state.FailingSources} source(s). Fix those first.",
            };
        }

        if (!state.IsEnforcing)
        {
            // The next step from p=none is p=quarantine, whatever the target
            // is, because that is the only move the planner will make: it
            // refuses none straight to reject, since quarantine sends failing
            // mail to junk and is recoverable where reject discards it.
            //
            // This said "Ready to move to p=reject" for a real domain sitting
            // at p=none and 100% authenticating. An operator who followed it
            // got "[REFUSED] Refusing to move acme.example from p=none
            // straight to p=reject" from the very next command. Advice the
            // product will not then carry out is worse than no advice: it
            // spends the operator's trust on the one screen whose whole job is
            // saying what to do next.
            var next = string.Equals(state.PolicyTarget, "quarantine", StringComparison.OrdinalIgnoreCase)
                ? "p=quarantine."
                : $"p=quarantine, the step before p={state.PolicyTarget}.";

            return new RolloutVerdict
            {
                Level = TriageLevel.Act,
                Headline = $"p=none with everything authenticating. Ready to move to {next}",
            };
        }

        // Enforcing, above the healthy threshold, and STILL losing mail.
        //
        // This was silent, and silence reads as nothing happening. A domain at
        // p=reject on 98.2% is refusing every one of the remaining 1.8%
        // outright: the customer's mail is bouncing and nobody is told,
        // because the pass rate looks good. An MSP is paid to notice exactly
        // that, so it says the count rather than the percentage - "42
        // refused" is actionable in a way that "98.2% passing" is not.
        if (state.IsEnforcing && state.Failing > 0)
        {
            var what = state.Policy == "reject" ? "refused outright" : "sent to junk";

            // Advancing to reject hardens junked mail into bounced mail, so
            // "ready to advance" is a decision while anything is still
            // failing, not a formality.
            var next = state.Policy == "quarantine" && state.PolicyTarget == "reject"
                ? " At p=reject they would be refused instead, so confirm none of them are the customer's before advancing."
                : " Worth confirming none of them were the customer's.";

            return new RolloutVerdict
            {
                Level = TriageLevel.Watch,
                Headline = $"p={state.Policy} at {state.PassRate}% passing. {state.Failing:N0} message(s) were "
                         + $"{what}.{next}",
            };
        }

        if (state.Policy == "quarantine" && state.PolicyTarget == "reject")
        {
            return new RolloutVerdict
            {
                Level = TriageLevel.Watch,
                Headline = "Quarantining with nothing failing. Ready to move to p=reject.",
            };
        }

        return new RolloutVerdict { Level = TriageLevel.Fine, Headline = "" };
    }
}
