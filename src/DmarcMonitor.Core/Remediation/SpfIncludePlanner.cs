using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Plans removing an include from a domain's SPF record.
///
/// Only ever for an include that resolves to no SPF record. Such an include
/// authorizes nothing, spends one of the ten lookups, and under RFC 7208 §5.2
/// makes the whole evaluation a permerror, so removing it cannot un-authorize
/// anybody. An include that merely has not sent lately is a different thing
/// and is deliberately not plannable here: the hygiene check words that as
/// evidence for a human, and this must not turn it into a write.
/// </summary>
public static class SpfIncludePlanner
{
    public static ChangePlan RemoveDeadInclude(string domain, string? currentRecord, string include)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(include);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var current = (currentRecord ?? "").Trim();
        var target = include.Trim().TrimEnd('.');

        var record = SpfRecord.Parse(current);
        if (!record.IsValid)
        {
            return ChangePlan.Refused(name, ChangeType.SpfIncludeRemove, name, current,
                current.Length == 0
                    ? $"No SPF record exists for {name}, so there is nothing to remove include:{target} from."
                    : $"The record is not an SPF record ({record.Error}). Refusing to edit it.");
        }

        var matching = record.Terms
            .Where(t => t.Name == "include" && t.Value.TrimEnd('.').Equals(target, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matching.Count == 0)
        {
            return new ChangePlan
            {
                Domain = name,
                Type = ChangeType.SpfIncludeRemove,
                RecordName = name,
                CurrentValue = current,
                ProposedValue = current,
                LookupsBefore = record.DirectLookups,
                LookupsAfter = record.DirectLookups,
                Summary = $"include:{target} is not in the SPF record for {name}",
            };
        }

        // Rebuilt from the terms as written, so spacing and qualifiers the
        // operator chose survive and only the one term goes.
        var kept = record.Terms.Where(t => !matching.Contains(t)).Select(t => t.Raw);
        var proposed = string.Join(' ', ["v=spf1", .. kept]);

        return new ChangePlan
        {
            Domain = name,
            Type = ChangeType.SpfIncludeRemove,
            RecordName = name,
            CurrentValue = current,
            ProposedValue = proposed,
            LookupsBefore = record.DirectLookups,
            LookupsAfter = record.DirectLookups - matching.Count,
            Summary = $"Remove include:{target} from the SPF record for {name}; it resolves to no SPF record and authorizes nothing",
        };
    }
}
