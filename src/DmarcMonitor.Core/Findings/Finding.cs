namespace DmarcMonitor.Core.Findings;

/// <summary>
/// What the source of a finding last saw. Only an engine sets it; a person's
/// decision about a finding lives in <see cref="AnalystStates"/> and never
/// moves this.
/// </summary>
public static class SourceStates
{
    /// <summary>The condition was there on the last successful observation.</summary>
    public const string Active = "active";

    /// <summary>
    /// Enough successful observations in a row did not show it - the type
    /// says how many. Resolution is evidence, so only a successful
    /// observation counts towards it.
    /// </summary>
    public const string Resolved = "resolved";

    /// <summary>
    /// The last observation of its scope failed. Nothing is known, and a
    /// finding in this state is never cleared: a collector that broke is not
    /// a condition that went away.
    /// </summary>
    public const string Unknown = "unknown";

    public static readonly IReadOnlyList<string> All = [Active, Resolved, Unknown];
}

/// <summary>What a person decided about a finding, apart from what its source sees.</summary>
public static class AnalystStates
{
    public const string Unreviewed = "unreviewed";
    public const string Investigating = "investigating";
    public const string ActionRequired = "action_required";
    public const string Benign = "benign";
    public const string AcceptedRisk = "accepted_risk";
    public const string Closed = "closed";

    public static readonly IReadOnlyList<string> All =
        [Unreviewed, Investigating, ActionRequired, Benign, AcceptedRisk, Closed];

    public static bool IsKnown(string state) => All.Contains(state, StringComparer.Ordinal);
}

/// <summary>
/// Where a change this product made stands between "the API accepted it" and
/// "the receivers behave as intended". A DNS edit is none of those on its own.
/// </summary>
public static class RemediationStages
{
    public const string Planned = "planned";
    public const string Applied = "applied";
    public const string DnsPending = "dns_pending";
    public const string DnsVerified = "dns_verified";
    public const string EffectivenessPending = "effectiveness_pending";

    public static readonly IReadOnlyList<string> All =
        [Planned, Applied, DnsPending, DnsVerified, EffectivenessPending];

    /// <summary>The stages a finding waits in for evidence rather than for a person.</summary>
    public static readonly IReadOnlyList<string> AwaitingVerification =
        [DnsPending, DnsVerified, EffectivenessPending];

    public static bool IsKnown(string stage) => All.Contains(stage, StringComparer.Ordinal);
}

/// <summary>What can happen to a finding, as finding_events records it.</summary>
public static class FindingEventKinds
{
    public const string Observed = "Observed";
    public const string SeverityChanged = "SeverityChanged";
    public const string TypeChanged = "TypeChanged";
    public const string SourceUnknown = "SourceUnknown";
    public const string ObservationAbsent = "ObservationAbsent";
    public const string SourceResolved = "SourceResolved";
    public const string Reopened = "Reopened";
    public const string Acknowledged = "Acknowledged";
    public const string AnalystStateChanged = "AnalystStateChanged";
    public const string ExceptionApplied = "ExceptionApplied";
    public const string ExceptionExpired = "ExceptionExpired";
    public const string ExceptionEnded = "ExceptionEnded";
    public const string RemediationStaged = "RemediationStaged";
    public const string ExpectedChanged = "ExpectedChanged";
    public const string TicketCreated = "TicketCreated";
    public const string TicketUpdated = "TicketUpdated";

    /// <summary>
    /// The kinds a destination is told about: what the source saw change and
    /// what a person decided. Not an observation counted towards resolution,
    /// not a moved expectation, and not the ticket a destination itself filed.
    /// </summary>
    public static readonly IReadOnlyList<string> Delivering =
    [
        Observed, SeverityChanged, TypeChanged, SourceUnknown, SourceResolved, Reopened,
        Acknowledged, AnalystStateChanged, ExceptionApplied, ExceptionExpired, ExceptionEnded, RemediationStaged,
    ];

    /// <summary>
    /// The kinds worth telling a destination about. A plain re-observation is
    /// not one: the finding's counters carry it, and a note per night on a
    /// ticket is how a ticket gets muted.
    /// </summary>
    public static readonly IReadOnlyList<string> Delivered =
        [Observed, SeverityChanged, TypeChanged, SourceResolved, Reopened, ExceptionApplied, ExceptionExpired];
}

/// <summary>
/// One thing that is wrong, however many observations have seen it. The
/// current state; <see cref="FindingEvent"/> is what happened to it.
/// </summary>
/// <remarks>
/// Metadata about a client and a pointer at the evidence, never the evidence:
/// <see cref="Title"/> is a derived line and <see cref="EvidenceRef"/> names
/// the row in the client's own file that holds the record text or the report.
/// A finding's identity is (organization, source, client, dedup key).
/// </remarks>
public sealed record Finding
{
    public required string Id { get; init; }
    public required string TenantId { get; init; }
    public required string ClientId { get; init; }
    public string? DomainId { get; init; }

    /// <summary>Which engine raised it; see <see cref="FindingSourceIds"/>.</summary>
    public required string SourceId { get; init; }

    /// <summary>One of <see cref="FindingTypes"/>.</summary>
    public required string Type { get; init; }

    /// <summary>The source's finer rule, where it has one.</summary>
    public string? Rule { get; init; }

    /// <summary>info, warning or critical.</summary>
    public required string Severity { get; init; }

    public required string Title { get; init; }

    /// <summary>The source's identity for the condition, the same on every observation of it.</summary>
    public required string DedupKey { get; init; }

    /// <summary>Where the evidence is, in the client's file: <c>kind:id</c>.</summary>
    public string? EvidenceRef { get; init; }

    /// <summary>What a resolving observation has to match, for types that verify against a known-good state.</summary>
    public string? ExpectedRef { get; init; }

    /// <summary>The finding this one answers - a remediation's drift.</summary>
    public string? RelatedFindingId { get; init; }

    public string SourceState { get; init; } = SourceStates.Active;
    public string AnalystState { get; init; } = AnalystStates.Unreviewed;
    public string? RemediationStage { get; init; }

    public required DateTimeOffset FirstObservedAt { get; init; }
    public required DateTimeOffset LastObservedAt { get; init; }
    public int ObservationCount { get; init; } = 1;

    /// <summary>Consecutive successful observations that did not show it.</summary>
    public int AbsentCount { get; init; }
    public int ReopenedCount { get; init; }
    public DateTimeOffset? SourceResolvedAt { get; init; }

    /// <summary>What the source adds beyond the title - numbers, windows, a model version. Never evidence.</summary>
    public string? PayloadJson { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }

    // ---- read with the row, for display -------------------------------------

    public string ClientSlug { get; init; } = "";
    public string ClientName { get; init; } = "";
    public string? Domain { get; init; }

    /// <summary>The exception hiding it from the queue, while one does.</summary>
    public FindingExceptionRecord? OpenException { get; init; }

    public bool IsExcepted => OpenException is not null;

    /// <summary>
    /// Whether it wants a person's attention: its source still sees it,
    /// nobody has closed it or called it benign, and no exception covers it.
    /// </summary>
    public bool InQueue =>
        !string.Equals(SourceState, SourceStates.Resolved, StringComparison.Ordinal)
        && AnalystState is not (AnalystStates.Closed or AnalystStates.Benign)
        && !IsExcepted;

    public bool AwaitsVerification =>
        RemediationStage is not null && RemediationStages.AwaitingVerification.Contains(RemediationStage, StringComparer.Ordinal);
}

/// <summary>One thing that happened to a finding, appended and never changed.</summary>
public sealed record FindingEvent
{
    public required string Id { get; init; }
    public required string FindingId { get; init; }
    public required DateTimeOffset At { get; init; }

    /// <summary>One of <see cref="FindingEventKinds"/>.</summary>
    public required string Kind { get; init; }

    /// <summary>A person, or the source id.</summary>
    public required string Actor { get; init; }
    public string? FromValue { get; init; }
    public string? ToValue { get; init; }
    public string? Note { get; init; }
    public string? PayloadJson { get; init; }
}

/// <summary>An event with the finding it happened to, for a page or a destination.</summary>
public sealed record FindingChange(FindingEvent Event, Finding Finding);

/// <summary>
/// A decision to live with a finding for a while. It hides the finding from
/// the queue and changes nothing about observation.
/// </summary>
public sealed record FindingExceptionRecord
{
    public required string Id { get; init; }
    public required string TenantId { get; init; }
    public required string ClientId { get; init; }
    public required string FindingId { get; init; }
    public required string Reason { get; init; }
    public required string Approver { get; init; }
    public required string CompensatingControl { get; init; }
    public required DateTimeOffset ApprovedAt { get; init; }
    public required DateTimeOffset ReviewAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? EndedAt { get; init; }
    public string? EndedReason { get; init; }
    public required string CreatedBy { get; init; }
    public DateTimeOffset CreatedAt { get; init; }

    public bool IsOpen => EndedAt is null;
}

/// <summary>What a source asks for when it wants an exception recorded.</summary>
public sealed record ExceptionRequest
{
    public required string Reason { get; init; }
    public required string Approver { get; init; }
    public required string CompensatingControl { get; init; }
    public required DateTimeOffset ReviewAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public required string By { get; init; }
}

/// <summary>One observation of a condition by a source: what it saw, and where the evidence is.</summary>
public sealed record Observation
{
    public required string TenantId { get; init; }
    public required string ClientId { get; init; }
    public string? DomainId { get; init; }
    public required string SourceId { get; init; }
    public required string Type { get; init; }
    public string? Rule { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public required string DedupKey { get; init; }
    public string? EvidenceRef { get; init; }

    /// <summary>Set on the first observation and kept: a re-observation does not move the goalposts.</summary>
    public string? ExpectedRef { get; init; }
    public string? RelatedFindingId { get; init; }
    public string? PayloadJson { get; init; }

    /// <summary>When it was seen; the lifecycle's clock when null.</summary>
    public DateTimeOffset? At { get; init; }
}

/// <summary>What observing did to the finding.</summary>
public enum ObserveOutcome
{
    /// <summary>A new finding.</summary>
    Created,

    /// <summary>Seen again; the counters moved and nothing else did.</summary>
    Unchanged,

    /// <summary>Seen again with a different severity or type.</summary>
    Changed,

    /// <summary>Its source had resolved it, and it is back: the same row, reopened.</summary>
    Reopened,

    /// <summary>Its source had lost sight of it, and sees it again.</summary>
    KnownAgain,
}

/// <summary>The finding after an observation, and what the observation did.</summary>
public sealed record Observed(Finding Finding, ObserveOutcome Outcome);

/// <summary>What reconciling a source's scope did.</summary>
/// <param name="Absent">Findings a successful observation did not show.</param>
/// <param name="Resolved">Of those, how many that observation resolved.</param>
public sealed record FindingReconciliation(int Absent, int Resolved);
