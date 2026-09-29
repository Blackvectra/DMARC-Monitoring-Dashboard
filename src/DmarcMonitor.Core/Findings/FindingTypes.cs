namespace DmarcMonitor.Core.Findings;

/// <summary>The engines that raise findings.</summary>
public static class FindingSourceIds
{
    /// <summary>The nightly read of every domain's records.</summary>
    public const string DnsScan = "dns-scan";

    /// <summary>What the aggregate reports say, and whether they keep arriving.</summary>
    public const string Reports = "reports";

    /// <summary>Changes this product applied, and whether they took.</summary>
    public const string Remediation = "remediation";

    /// <summary>Statistical baselines and, if it earns it, the model.</summary>
    public const string Anomaly = "anomaly";
}

/// <summary>
/// What a source must be able to say about a type before the type exists:
/// what makes two observations the same finding, where the evidence is, what
/// resolves it, and how severity is decided.
/// </summary>
public sealed record FindingTypeDefinition
{
    public required string Id { get; init; }
    public required string SourceId { get; init; }

    /// <summary>What the dedup key is made of.</summary>
    public required string Identity { get; init; }

    /// <summary>What <see cref="Finding.EvidenceRef"/> points at.</summary>
    public required string Evidence { get; init; }

    /// <summary>What a resolving observation is.</summary>
    public required string Resolution { get; init; }

    /// <summary>How the source decides severity.</summary>
    public required string SeverityRule { get; init; }

    /// <summary>
    /// Consecutive successful observations without the condition before the
    /// source resolves it. One for a DNS record that reads correctly; more for
    /// something that has to stay quiet for a while to count as gone.
    /// </summary>
    public int ResolveAfterAbsent { get; init; } = 1;
}

/// <summary>
/// The finding types this product raises. Every one has a source that
/// defines its identity, evidence, resolution and severity; a type nothing
/// raises is not here, however plausible it sounds.
/// </summary>
public static class FindingTypes
{
    /// <summary>A record other than DMARC or SPF changed, or was published or withdrawn: MTA-STS, TLS-RPT.</summary>
    public const string DnsDrift = "DNS_DRIFT";

    /// <summary>The DMARC policy loosened, the report address was lost, or the record was removed or no longer parses.</summary>
    public const string DmarcPolicyWeakened = "DMARC_POLICY_WEAKENED";

    /// <summary>The DMARC record changed in a way that is not weaker.</summary>
    public const string DmarcPolicyChanged = "DMARC_POLICY_CHANGED";

    /// <summary>SPF was removed, no longer parses, or is published twice.</summary>
    public const string SpfInvalid = "SPF_INVALID";

    /// <summary>SPF changed: a term removed, its all weakened, or a term added.</summary>
    public const string SpfChanged = "SPF_CHANGED";

    /// <summary>A domain that had reports arriving stopped, while collection kept working.</summary>
    public const string ReportingStopped = "REPORTING_STOPPED";

    /// <summary>A change this product applied, until DNS and the reports show it took.</summary>
    public const string RemediationPendingVerification = "REMEDIATION_PENDING_VERIFICATION";

    private static readonly IReadOnlyList<FindingTypeDefinition> Definitions =
    [
        new()
        {
            Id = DnsDrift,
            SourceId = FindingSourceIds.DnsScan,
            Identity = "domain and record type",
            Evidence = "the drift event in the client's file (drift:<id>), which holds the record before and after",
            Resolution = "one successful read of the record that matches what was published before the change",
            SeverityRule = "warning when the record was withdrawn, info otherwise (DnsDrift.cs)",
        },
        new()
        {
            Id = DmarcPolicyWeakened,
            SourceId = FindingSourceIds.DnsScan,
            Identity = "domain and record type: one finding per DMARC record, whatever it does next",
            Evidence = "the drift event in the client's file (drift:<id>)",
            Resolution = "one successful read of the DMARC record that matches what was published before the change",
            SeverityRule = "critical: p or sp loosened, a report address lost, the record removed or unparseable (DnsDrift.cs)",
        },
        new()
        {
            Id = DmarcPolicyChanged,
            SourceId = FindingSourceIds.DnsScan,
            Identity = "domain and record type",
            Evidence = "the drift event in the client's file (drift:<id>)",
            Resolution = "one successful read of the DMARC record that matches what was published before the change",
            SeverityRule = "warning when tightened, pct lowered or alignment changed; info otherwise (DnsDrift.cs)",
        },
        new()
        {
            Id = SpfInvalid,
            SourceId = FindingSourceIds.DnsScan,
            Identity = "domain and record type",
            Evidence = "the drift event in the client's file (drift:<id>)",
            Resolution = "one successful read of the SPF record that matches what was published before the change",
            SeverityRule = "critical: removed, no longer parses, or published more than once (DnsDrift.cs)",
        },
        new()
        {
            Id = SpfChanged,
            SourceId = FindingSourceIds.DnsScan,
            Identity = "domain and record type",
            Evidence = "the drift event in the client's file (drift:<id>)",
            Resolution = "one successful read of the SPF record that matches what was published before the change",
            SeverityRule = "warning when a term was removed or all weakened; info for an added term (DnsDrift.cs)",
        },
        new()
        {
            Id = ReportingStopped,
            SourceId = FindingSourceIds.Reports,
            Identity = "domain",
            Evidence = "the domain's newest report in the client's file (report:<id>)",
            Resolution = "reports covering the domain again on three consecutive nightly observations, with collection healthy throughout",
            SeverityRule = "warning; critical once the DMARC record's report address is also gone",
            ResolveAfterAbsent = 3,
        },
        new()
        {
            Id = RemediationPendingVerification,
            SourceId = FindingSourceIds.Remediation,
            Identity = "the applied change",
            Evidence = "the change in the client's file (change:<id>), which holds the value written",
            Resolution = "the change staged through DNS verified to effectiveness verified, or fourteen days after DNS verification with no reporting evidence",
            SeverityRule = "info while it waits; warning when DNS still does not serve the value after a day",
        },
    ];

    public static IReadOnlyDictionary<string, FindingTypeDefinition> All { get; } =
        Definitions.ToDictionary(d => d.Id, d => d, StringComparer.Ordinal);

    public static FindingTypeDefinition Get(string id) =>
        All.TryGetValue(id, out var definition)
            ? definition
            : throw new ArgumentException($"No finding type '{id}' is defined; a type needs a source that says what identifies, evidences and resolves it.", nameof(id));
}
