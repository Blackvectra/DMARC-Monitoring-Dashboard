namespace DmarcMonitor.Core.Remediation;

/// <summary>The kinds of change this can plan. Values match the dns_change_plans CHECK constraint.</summary>
public static class ChangeType
{
    public const string DmarcPolicy = "dmarc-policy";
    public const string SpfIncludeRemove = "spf-include-remove";
    public const string MtaSts = "mta-sts";
    public const string TlsRpt = "tls-rpt";
}

/// <summary>
/// A change to one DNS record, worked out but not yet made.
///
/// A plan carries its own refusal. Blockers are the reasons it must not be
/// applied and there is deliberately no way to override them: every one
/// exists because applying would break somebody's mail. Warnings are things
/// an operator should read before confirming, and do not stop anything.
///
/// Kept even when refused, because "we could not advance this domain and here
/// is why" is itself the thing an operator needs to act on.
/// </summary>
public sealed record ChangePlan
{
    public required string Domain { get; init; }

    /// <summary>One of the <see cref="ChangeType"/> values.</summary>
    public required string Type { get; init; }

    /// <summary>The DNS name written to, for example _dmarc.example.com.</summary>
    public required string RecordName { get; init; }

    public string RecordType { get; init; } = "TXT";

    /// <summary>What was published when the plan was made. Empty when nothing was.</summary>
    public string CurrentValue { get; init; } = "";

    /// <summary>What will be published. Equal to CurrentValue when nothing needs to change.</summary>
    public string ProposedValue { get; init; } = "";

    public IReadOnlyList<string> Blockers { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>One sentence saying what the plan does, or why it was refused.</summary>
    public required string Summary { get; init; }

    /// <summary>SPF lookups the record costs before and after, when the change affects them.</summary>
    public int? LookupsBefore { get; init; }
    public int? LookupsAfter { get; init; }

    public bool IsSafe => Blockers.Count == 0;

    /// <summary>
    /// Nothing to write. A safe no-op, so re-running a remediation is
    /// idempotent rather than churning the zone.
    /// </summary>
    public bool IsNoop => IsSafe && string.Equals(CurrentValue, ProposedValue, StringComparison.Ordinal);

    public static ChangePlan Refused(string domain, string type, string recordName, string current, string reason) => new()
    {
        Domain = domain,
        Type = type,
        RecordName = recordName,
        CurrentValue = current,
        ProposedValue = current,
        Blockers = [reason],
        Summary = "Refused: " + reason,
    };
}
