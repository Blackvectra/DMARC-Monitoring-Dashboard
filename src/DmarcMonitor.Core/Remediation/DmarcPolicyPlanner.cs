using System.Globalization;
using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Plans changes to a domain's DMARC record.
///
/// Advancing policy is the point of the whole product, and it is also the
/// change most capable of dropping legitimate mail. So this refuses to skip a
/// rung: none to reject in one step is refused in favour of none to
/// quarantine, because quarantine is recoverable and reject is not. A pct ramp
/// exists for the same reason: p=reject pct=25 applies the policy to a quarter
/// of failing mail, so a mistake costs a quarter as much while the reports
/// still show what would have happened to the rest.
///
/// Pure. Reading the record and writing it back are somebody else's problem,
/// so every rule here can be tested against every record without a resolver.
/// </summary>
public static class DmarcPolicyPlanner
{
    private static readonly string[] Rungs = ["none", "quarantine", "reject"];

    /// <summary>
    /// Plans moving a domain to a policy.
    /// </summary>
    /// <param name="domain">The domain, without the _dmarc prefix.</param>
    /// <param name="currentRecord">What is published now, or empty for nothing.</param>
    /// <param name="targetPolicy">none, quarantine or reject.</param>
    /// <param name="targetPercent">The pct tag to publish. 100 removes the tag, which means the same thing.</param>
    /// <param name="allowSkip">
    /// Permits none to reject in one step. There is no flag for it on the
    /// command line by design; it exists for a domain whose operator has run
    /// quarantine somewhere else and can say so in the reason.
    /// </param>
    public static ChangePlan Advance(
        string domain, string? currentRecord, string targetPolicy, int targetPercent = 100, bool allowSkip = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPolicy);
        ArgumentOutOfRangeException.ThrowIfLessThan(targetPercent, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(targetPercent, 100);

        var name = Name(domain);
        var current = (currentRecord ?? "").Trim();
        var target = targetPolicy.Trim().ToLowerInvariant();

        if (Array.IndexOf(Rungs, target) < 0)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                $"'{targetPolicy}' is not a DMARC policy. Use none, quarantine or reject.");
        }

        if (current.Length == 0)
        {
            // No record at all. Starting anywhere above none with no reports
            // to go on is how mail nobody knew about gets lost.
            if (target != "none" && !allowSkip)
            {
                return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                    $"No DMARC record exists for {domain}. Publish p=none first and collect at least two weeks of "
                    + "reports before enforcing, otherwise legitimate senders nobody knew about are affected silently.");
            }

            var value = $"v=DMARC1; p={target}; rua=mailto:dmarc@{domain}";
            return new ChangePlan
            {
                Domain = domain,
                Type = ChangeType.DmarcPolicy,
                RecordName = name,
                CurrentValue = current,
                ProposedValue = value,
                Warnings = ["The rua address is a placeholder. Point it at the mailbox this tool reads, or no reports will arrive."],
                Summary = $"Create a DMARC record for {domain} at p={target}",
            };
        }

        var record = DmarcRecord.Parse(current);
        if (!record.IsValid)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                $"The record at {name} is not a DMARC record ({record.Error}). Refusing to overwrite it.");
        }

        var from = record.Policy.ToLowerInvariant();
        var fromRung = Array.IndexOf(Rungs, from);
        var toRung = Array.IndexOf(Rungs, target);

        if (fromRung < 0)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                $"The record has p={record.Policy}, which is not a policy this understands. Fix it by hand first.");
        }

        if (from == target && record.Percent == targetPercent)
        {
            return new ChangePlan
            {
                Domain = domain,
                Type = ChangeType.DmarcPolicy,
                RecordName = name,
                CurrentValue = current,
                ProposedValue = current,
                Summary = $"{domain} is already at p={target}" + (targetPercent < 100 ? $" pct={targetPercent}" : ""),
            };
        }

        if (toRung - fromRung > 1 && !allowSkip)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                $"Refusing to move {domain} from p={from} straight to p=reject. Go to p=quarantine first: "
                + "quarantine sends failing mail to junk and is recoverable, reject discards it and is not.");
        }

        var warnings = new List<string>();
        if (toRung < fromRung)
        {
            warnings.Add($"This weakens enforcement from p={from} to p={target}.");
        }

        if (record.Rua.Length == 0)
        {
            warnings.Add("No rua tag. Enforcing without aggregate reports means nobody sees what the policy is doing.");
        }

        var edits = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["p"] = target,
            ["pct"] = targetPercent == 100 ? null : targetPercent.ToString(CultureInfo.InvariantCulture),
        };

        var pctNote = targetPercent < 100 ? $" at pct={targetPercent}" : "";

        return new ChangePlan
        {
            Domain = domain,
            Type = ChangeType.DmarcPolicy,
            RecordName = name,
            CurrentValue = current,
            ProposedValue = Rebuild(current, edits),
            Warnings = warnings,
            Summary = $"Move {domain} from p={from} to p={target}{pctNote}",
        };
    }

    /// <summary>
    /// Plans closing a subdomain policy that is weaker than the domain's.
    /// </summary>
    /// <remarks>
    /// Removes the sp tag rather than setting it equal to p. Absent, subdomains
    /// inherit, and keep inheriting when the domain advances next; set equal,
    /// somebody has to remember to change both, which is how the weak sp got
    /// there in the first place.
    /// </remarks>
    public static ChangePlan FixSubdomainPolicy(string domain, string? currentRecord)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var name = Name(domain);
        var current = (currentRecord ?? "").Trim();

        var record = DmarcRecord.Parse(current);
        if (!record.IsValid)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                current.Length == 0
                    ? $"No DMARC record exists for {domain}, so there is no subdomain policy to fix."
                    : $"The record at {name} is not a DMARC record ({record.Error}). Refusing to edit it.");
        }

        var noop = new ChangePlan
        {
            Domain = domain,
            Type = ChangeType.DmarcPolicy,
            RecordName = name,
            CurrentValue = current,
            ProposedValue = current,
            Summary = $"Subdomains of {domain} already follow p={record.Policy}",
        };

        if (record.SubdomainPolicy.Length == 0)
        {
            return noop;
        }

        var spRung = Array.IndexOf(Rungs, record.SubdomainPolicy.ToLowerInvariant());
        var pRung = Array.IndexOf(Rungs, record.Policy.ToLowerInvariant());

        if (spRung < 0 || pRung < 0)
        {
            return ChangePlan.Refused(domain, ChangeType.DmarcPolicy, name, current,
                $"The record has p={record.Policy} sp={record.SubdomainPolicy}, which is not a pair this understands. Fix it by hand first.");
        }

        // An sp stronger than p is a choice somebody made on purpose and
        // must be left alone: it is the one case where removing the tag
        // would weaken something.
        if (spRung >= pRung)
        {
            return noop with { Summary = $"Subdomains of {domain} are at sp={record.SubdomainPolicy}, which is not weaker than p={record.Policy}" };
        }

        return new ChangePlan
        {
            Domain = domain,
            Type = ChangeType.DmarcPolicy,
            RecordName = name,
            CurrentValue = current,
            ProposedValue = Rebuild(current, new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase) { ["sp"] = null }),
            Summary = $"Remove sp={record.SubdomainPolicy} from {domain} so subdomains follow p={record.Policy}",
        };
    }

    /// <summary>
    /// Rebuilds a record with some tags changed, keeping every other tag the
    /// operator had set and in the order they set them.
    /// </summary>
    /// <remarks>
    /// v= must come first (RFC 7489 §6.3) and p= goes second by convention.
    /// A null edit removes the tag.
    /// </remarks>
    internal static string Rebuild(string current, IReadOnlyDictionary<string, string?> edits)
    {
        var order = new List<string>();
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in current.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) { continue; }

            var key = part[..equals].Trim().ToLowerInvariant();
            if (!tags.ContainsKey(key)) { order.Add(key); }
            tags[key] = part[(equals + 1)..].Trim();
        }

        foreach (var (key, value) in edits)
        {
            var lower = key.ToLowerInvariant();
            if (value is null)
            {
                tags.Remove(lower);
                order.Remove(lower);
            }
            else
            {
                if (!tags.ContainsKey(lower)) { order.Add(lower); }
                tags[lower] = value;
            }
        }

        tags["v"] = "DMARC1";

        var parts = new List<string> { "v=DMARC1" };
        if (tags.TryGetValue("p", out var p)) { parts.Add($"p={p}"); }
        parts.AddRange(order.Where(k => k is not ("v" or "p")).Select(k => $"{k}={tags[k]}"));

        return string.Join("; ", parts);
    }

    private static string Name(string domain) => "_dmarc." + domain.Trim().TrimEnd('.').ToLowerInvariant();
}
