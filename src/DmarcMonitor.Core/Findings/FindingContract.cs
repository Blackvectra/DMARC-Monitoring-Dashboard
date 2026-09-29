using System.Text.Json;
using System.Text.Json.Serialization;

namespace DmarcMonitor.Core.Findings;

/// <summary>
/// One finding as it leaves this product: the contract with whatever
/// receives it, written down in docs/WEBHOOKS.md as
/// <c>dmarc-monitor.finding.v1</c>.
/// </summary>
/// <remarks>
/// <para>
/// It carries what a triage layer needs to file and dedup the finding - its
/// identity, its type and severity, what its source and a person last said
/// about it - and where the evidence is. It never carries the evidence: no
/// record text, no report, nothing that belongs in the client's own file.
/// A receiver that needs the record follows the link.
/// </para>
/// <para>
/// Adding a field is safe; renaming or removing one is a new schema version,
/// because a receiver somewhere is reading the old name and will not be told.
/// </para>
/// </remarks>
public sealed record FindingContract
{
    public const string CurrentSchema = "dmarc-monitor.finding.v1";
    public const string Version = "finding.v1";

    public string Schema { get; init; } = CurrentSchema;
    public string PayloadVersion { get; init; } = Version;

    /// <summary>The finding event this describes: unique per delivery, the same on every retry.</summary>
    public required string Id { get; init; }
    public required string FindingId { get; init; }
    public required string SourceId { get; init; }
    public required string TenantId { get; init; }
    public required FindingContractOrganization Organization { get; init; }
    public required FindingContractClient Client { get; init; }
    public string? Domain { get; init; }
    public required string DedupKey { get; init; }
    public required string Type { get; init; }
    public string? Rule { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }

    /// <summary>The control this finding is about, once a catalog names one. Absent until then.</summary>
    public string? ControlId { get; init; }

    /// <summary>Where the evidence can be opened, when the destination knows the dashboard's address.</summary>
    [JsonPropertyName("evidenceUri")]
    public string? EvidenceLink { get; init; }

    /// <summary>The evidence's internal identifier in the source system.</summary>
    public string? EvidenceRef { get; init; }

    public required DateTimeOffset ObservedAt { get; init; }
    public required DateTimeOffset LastObservedAt { get; init; }
    public int ObservationCount { get; init; }
    public required string SourceState { get; init; }
    public required string AnalystState { get; init; }
    public string? RemediationStage { get; init; }

    /// <summary>What happened that caused this to be sent; one of <see cref="FindingEventKinds"/>.</summary>
    public required string EventKind { get; init; }
    public required DateTimeOffset EventAt { get; init; }
    public string? EventNote { get; init; }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static FindingContract? FromJson(string json) => JsonSerializer.Deserialize<FindingContract>(json, Json);

    /// <summary>The contract for one event on a finding.</summary>
    /// <param name="linkBase">The dashboard's address, or null for no link.</param>
    public static FindingContract For(Finding finding, FindingEvent change, string tenantSlug, string? linkBase)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(change);

        return new FindingContract
        {
            Id = change.Id,
            FindingId = finding.Id,
            SourceId = finding.SourceId,
            TenantId = finding.TenantId,
            Organization = new FindingContractOrganization(finding.TenantId, tenantSlug),
            Client = new FindingContractClient(finding.ClientId, finding.ClientSlug, finding.ClientName),
            Domain = finding.Domain,
            DedupKey = finding.DedupKey,
            Type = finding.Type,
            Rule = finding.Rule,
            Severity = finding.Severity,
            Title = finding.Title,
            EvidenceLink = linkBase is not null && finding.Domain is not null
                ? linkBase.TrimEnd('/') + "/domains/" + Uri.EscapeDataString(finding.Domain)
                : null,
            EvidenceRef = finding.EvidenceRef,
            ObservedAt = finding.FirstObservedAt,
            LastObservedAt = finding.LastObservedAt,
            ObservationCount = finding.ObservationCount,
            SourceState = finding.SourceState,
            AnalystState = finding.AnalystState,
            RemediationStage = finding.RemediationStage,
            EventKind = change.Kind,
            EventAt = change.At,
            EventNote = change.Note,
        };
    }
}

public sealed record FindingContractOrganization(string Id, string Slug);

public sealed record FindingContractClient(string Id, string Slug, string Name);
