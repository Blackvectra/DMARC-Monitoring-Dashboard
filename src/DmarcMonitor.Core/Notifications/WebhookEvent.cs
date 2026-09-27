using System.Text.Json;
using System.Text.Json.Serialization;

namespace DmarcMonitor.Core.Notifications;

/// <summary>
/// One thing sent to a webhook: what happened, to which client's domain, how
/// much it matters, and where the evidence is.
/// </summary>
/// <remarks>
/// <para>
/// The shape is a contract with whoever receives it, written down in
/// docs/WEBHOOKS.md. Adding a field is safe; renaming or removing one is a
/// new <see cref="Schema"/> version, because a receiver somewhere is reading
/// the old name and will not be told.
/// </para>
/// <para>
/// It carries what somebody needs to decide whether to act, and a link to the
/// rest. The records' old and new values are included because a DNS change
/// is unreadable without them and they are public anyway; nothing from a
/// client's reports is.
/// </para>
/// </remarks>
public sealed record WebhookEvent
{
    public const string CurrentSchema = "dmarc-monitor.event.v1";
    public const string DnsDriftType = "dns.drift";
    public const string PingType = "ping";

    public string Schema { get; init; } = CurrentSchema;

    /// <summary>Stable across retries, so a receiver can tell a redelivery from a second change.</summary>
    public required string Id { get; init; }

    public required string Type { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
    public required WebhookOrganization Organization { get; init; }
    public WebhookClient? Client { get; init; }
    public string? Domain { get; init; }

    /// <summary>info, warning or critical, as the product rated it.</summary>
    public string? Severity { get; init; }

    public string? Summary { get; init; }

    /// <summary>
    /// True when this product changed the domain's DNS itself shortly before:
    /// a change somebody here made, not one the client made without saying.
    /// Absent on a ping, which is about no change at all.
    /// </summary>
    public bool? WasExpected { get; init; }

    public WebhookDnsDrift? DnsDrift { get; init; }

    /// <summary>The domain's page on the dashboard, when the webhook was given the dashboard's address.</summary>
    public string? Link { get; init; }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static WebhookEvent? FromJson(string json) => JsonSerializer.Deserialize<WebhookEvent>(json, Json);
}

public sealed record WebhookOrganization(string Id, string Slug);

public sealed record WebhookClient(string Id, string Slug, string Name);

public sealed record WebhookDnsDrift(string RecordType, string? OldValue, string? NewValue);
