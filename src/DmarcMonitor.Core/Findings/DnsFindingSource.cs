using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Findings;

/// <summary>
/// The DNS scan as a source of findings: what a stored reading says about
/// the domain's open findings, and what the changes it found raise.
/// </summary>
/// <remarks>
/// <para>
/// A finding here is one record of one domain, keyed on the two, whatever
/// the record does after the first change: a policy that was loosened and
/// is then removed is one finding whose type and severity moved, not two
/// tickets for one broken record. Its expected state is the record as it
/// was before the first change, and only a successful read that serves that
/// record again resolves it. A read that serves anything else - a further
/// change, the same drift another night - is the condition still there.
/// </para>
/// <para>
/// A read that failed says nothing about the domain, so the findings it
/// could not see are marked unknown and none is cleared. A domain that does
/// not exist answered, with nothing published.
/// </para>
/// </remarks>
public sealed class DnsFindingSource(string databasePath, TimeProvider? clock = null)
{
    /// <summary>The scan runs nightly.</summary>
    public const int ExpectedEveryHours = 24;

    private const string KeyPrefix = "dns:";
    private const string AbsentRef = "rec:absent";

    private readonly FindingLifecycle _lifecycle = new(databasePath, clock);
    private readonly RemediationFindingSource _remediation = new(databasePath, clock);

    /// <summary>What one stored reading did to the domain's findings.</summary>
    /// <param name="Observed">Findings the reading showed, new or again.</param>
    /// <param name="Absent">Findings whose record read as it did before the change.</param>
    /// <param name="Unknown">Findings a failed read could not see.</param>
    public sealed record Recorded(int Observed, int Absent, int Unknown);

    /// <summary>A finding's identity: the domain and the record.</summary>
    public static string DedupKey(string domainId, string recordType) => KeyPrefix + domainId + ":" + recordType;

    /// <summary>
    /// What a resolving read has to serve, from the record's text: a hash,
    /// so the organization's database holds no record value, and a marker
    /// for a record that was not published.
    /// </summary>
    public static string RecordRef(string? text) =>
        text is null
            ? AbsentRef
            : "rec:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.Trim()))).ToLowerInvariant();

    /// <summary>
    /// The finding's title: what changed, in the record's own vocabulary and
    /// never its contents. A policy, a percentage, an alignment mode and the
    /// all qualifier are enumerations; an address or a mechanism is the
    /// record, and stays in the client's file behind the evidence. The drift
    /// event keeps the full summary for the DNS changes page.
    /// </summary>
    public static string TitleFor(DriftChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        var label = change.RecordType switch
        {
            "spf" => "SPF",
            "dmarc" => "DMARC",
            "mta-sts" => "MTA-STS",
            "tls-rpt" => "TLS-RPT",
            _ => change.RecordType.ToUpperInvariant(),
        };

        switch (change.Rule)
        {
            case "record_removed": return label + ": the record was removed.";
            case "record_published": return label + ": a record was published.";
            case "record_changed": return label + ": the record changed.";
            case "rewritten": return label + ": the record was rewritten with the same meaning.";
            case "no_longer_parses": return label + ": the record no longer parses.";
            case "multiple_records": return "SPF: more than one record is published, so every SPF check fails.";
        }

        return change.RecordType switch
        {
            "spf" => SpfTitle(change),
            "dmarc" => DmarcTitle(change),
            _ => label + ": the record changed.",
        };
    }

    private static string SpfTitle(DriftChange change)
    {
        var before = change.OldValue is null ? null : SpfRecord.Parse(change.OldValue);
        var after = change.NewValue is null ? null : SpfRecord.Parse(change.NewValue);
        if (before is not { IsValid: true } || after is not { IsValid: true }) { return "SPF: the record changed."; }

        var oldTerms = before.Terms.Where(t => t.Name != "all").Select(t => t.Raw).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newTerms = after.Terms.Where(t => t.Name != "all").Select(t => t.Raw).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var removed = oldTerms.Except(newTerms, StringComparer.OrdinalIgnoreCase).Count();
        var added = newTerms.Except(oldTerms, StringComparer.OrdinalIgnoreCase).Count();
        var oldAll = before.All?.Raw ?? "(no all)";
        var newAll = after.All?.Raw ?? "(no all)";

        var parts = new List<string>();
        if (removed > 0) { parts.Add(removed == 1 ? "a term was removed" : removed.ToString(CultureInfo.InvariantCulture) + " terms were removed"); }
        if (added > 0) { parts.Add(added == 1 ? "a term was added" : added.ToString(CultureInfo.InvariantCulture) + " terms were added"); }
        if (!string.Equals(oldAll, newAll, StringComparison.OrdinalIgnoreCase)) { parts.Add(oldAll + " → " + newAll); }
        return parts.Count == 0 ? "SPF: the record changed." : "SPF: " + string.Join(", ", parts) + ".";
    }

    private static string DmarcTitle(DriftChange change)
    {
        var before = change.OldValue is null ? null : DmarcRecord.Parse(change.OldValue);
        var after = change.NewValue is null ? null : DmarcRecord.Parse(change.NewValue);
        if (before is not { IsValid: true } || after is not { IsValid: true }) { return "DMARC: the record changed."; }

        static string Show(string value) => value.Length == 0 ? "(none)" : value;
        var parts = new List<string>();
        if (!string.Equals(before.Policy, after.Policy, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add("p=" + Show(before.Policy) + " → p=" + Show(after.Policy));
        }
        if (!string.Equals(before.EffectiveSubdomainPolicy, after.EffectiveSubdomainPolicy, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add("sp=" + Show(before.EffectiveSubdomainPolicy) + " → sp=" + Show(after.EffectiveSubdomainPolicy));
        }
        if (before.Percent != after.Percent)
        {
            parts.Add("pct=" + before.Percent.ToString(CultureInfo.InvariantCulture) + " → pct=" + after.Percent.ToString(CultureInfo.InvariantCulture));
        }
        if (after.Rua.Length == 0 && before.Rua.Length > 0) { parts.Add("reports (rua) removed"); }
        else if (change.Rule is "rua_removed") { parts.Add("a report address was taken away"); }
        else if (change.Rule is "rua_changed" || !string.Equals(before.Rua, after.Rua, StringComparison.OrdinalIgnoreCase)) { parts.Add("report address changed"); }
        if (before.StrictDkim != after.StrictDkim || before.StrictSpf != after.StrictSpf)
        {
            parts.Add("alignment adkim=" + (before.StrictDkim ? "s" : "r") + "/aspf=" + (before.StrictSpf ? "s" : "r") + " → adkim="
                + (after.StrictDkim ? "s" : "r") + "/aspf=" + (after.StrictSpf ? "s" : "r"));
        }
        return parts.Count == 0 ? "DMARC: the record changed." : "DMARC: " + string.Join(", ", parts) + ".";
    }

    /// <summary>The finding type a change raises, from the rule that decided its severity.</summary>
    public static string TypeFor(DriftChange change)
    {
        ArgumentNullException.ThrowIfNull(change);

        return change.RecordType switch
        {
            "spf" => change.Rule is "multiple_records" or "record_removed" or "no_longer_parses"
                ? FindingTypes.SpfInvalid
                : FindingTypes.SpfChanged,
            "dmarc" => change.Rule is "record_removed" or "no_longer_parses" or "policy_loosened" or "subdomain_policy_loosened" or "rua_removed"
                ? FindingTypes.DmarcPolicyWeakened
                : FindingTypes.DmarcPolicyChanged,
            _ => FindingTypes.DnsDrift,
        };
    }

    /// <summary>Feeds one stored reading into the lifecycle.</summary>
    public async Task<Recorded> RecordAsync(
        SnapshotSave save, PublishedRecords published, DnsCheckStatus status, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(save);
        ArgumentNullException.ThrowIfNull(published);

        if (!save.Stored || save.DomainId is null || save.TenantId is null || save.ClientId is null)
        {
            return new Recorded(0, 0, 0);
        }

        if (status == DnsCheckStatus.Failed)
        {
            var unknown = await _lifecycle.MarkUnknownAsync(save.TenantId, save.ClientId, FindingSourceIds.DnsScan, save.DomainId,
                "the lookup failed, so what the domain publishes tonight is not known", now, ct).ConfigureAwait(false);
            return new Recorded(0, 0, unknown);
        }

        // A successful read: what each record says now, and which of them
        // changed since the last read.
        var current = Current(published, status);
        var changes = save.Drift.ToDictionary(c => c.RecordType, c => c, StringComparer.Ordinal);
        var handled = new HashSet<string>(StringComparer.Ordinal);
        var applied = await _remediation.ExpectedAsync(save.TenantId, save.ClientId, save.DomainId, ct).ConfigureAwait(false);
        int observed = 0, absent = 0;

        foreach (var finding in await _lifecycle.Store.OpenForScopeAsync(save.TenantId, save.ClientId, FindingSourceIds.DnsScan, save.DomainId, ct).ConfigureAwait(false))
        {
            var recordType = RecordTypeOf(finding.DedupKey);
            if (recordType is null) { continue; }
            handled.Add(recordType);

            if (string.Equals(RecordRef(current.GetValueOrDefault(recordType)), finding.ExpectedRef, StringComparison.Ordinal))
            {
                // The record reads as it did before the change: the one
                // observation that resolves a drift finding.
                await _lifecycle.AbsentAsync(finding, now, ct).ConfigureAwait(false);
                absent++;
                continue;
            }

            if (changes.TryGetValue(recordType, out var change))
            {
                await _lifecycle.ObserveAsync(Observation(save, change, now), ct).ConfigureAwait(false);
            }
            else
            {
                // Still drifted, unchanged since last night: seen again.
                await _lifecycle.ObserveAsync(new Observation
                {
                    TenantId = finding.TenantId,
                    ClientId = finding.ClientId,
                    DomainId = finding.DomainId,
                    SourceId = FindingSourceIds.DnsScan,
                    Type = finding.Type,
                    Rule = finding.Rule,
                    Severity = finding.Severity,
                    Title = finding.Title,
                    DedupKey = finding.DedupKey,
                    At = now,
                }, ct).ConfigureAwait(false);
            }
            observed++;
        }

        foreach (var change in save.Drift)
        {
            if (handled.Contains(change.RecordType)) { continue; }
            if (applied.TryGetValue(change.RecordType, out var expected)
                && string.Equals(RecordRef(change.NewValue), expected, StringComparison.Ordinal))
            {
                // The value this product wrote, arriving in DNS: not drift.
                // The change's own finding is verified by this read, below.
                continue;
            }
            await _lifecycle.ObserveAsync(Observation(save, change, now), ct).ConfigureAwait(false);
            observed++;
        }

        // A change this product applied is verified by the same read.
        await _remediation.ObserveDomainAsync(save.TenantId, save.ClientId, save.DomainId, current, now, ct).ConfigureAwait(false);

        return new Recorded(observed, absent, 0);
    }

    private static Observation Observation(SnapshotSave save, DriftChange change, DateTimeOffset now) => new()
    {
        TenantId = save.TenantId!,
        ClientId = save.ClientId!,
        DomainId = save.DomainId,
        SourceId = FindingSourceIds.DnsScan,
        Type = TypeFor(change),
        Rule = change.Rule,
        Severity = change.Severity,
        Title = TitleFor(change),
        DedupKey = DedupKey(save.DomainId!, change.RecordType),
        EvidenceRef = change.EventId is null ? null : "drift:" + change.EventId,
        ExpectedRef = RecordRef(change.OldValue),
        PayloadJson = change.WasExpected ? """{"wasExpected":true}""" : null,
        At = now,
    };

    /// <summary>What each record says in this reading; a record not published is absent from the map.</summary>
    internal static Dictionary<string, string> Current(PublishedRecords published, DnsCheckStatus status)
    {
        var current = new Dictionary<string, string>(StringComparer.Ordinal);
        if (status == DnsCheckStatus.NoSuchDomain) { return current; }

        if (published.SpfRecords.Count > 1)
        {
            // Never equal to any single record that was published before, so
            // a second SPF record is a fault until only one is left.
            current["spf"] = "multiple:" + string.Join("\n", published.SpfRecords.Order(StringComparer.Ordinal));
        }
        else if (published.SpfRecords.Count == 1)
        {
            current["spf"] = published.SpfRecords[0];
        }
        if (published.DmarcRecord is not null) { current["dmarc"] = published.DmarcRecord; }
        if (published.MtaStsRecord is not null) { current["mta-sts"] = published.MtaStsRecord; }
        if (published.TlsRptRecord is not null) { current["tls-rpt"] = published.TlsRptRecord; }
        return current;
    }

    private static string? RecordTypeOf(string dedupKey)
    {
        if (!dedupKey.StartsWith(KeyPrefix, StringComparison.Ordinal)) { return null; }
        var at = dedupKey.LastIndexOf(':');
        return at < KeyPrefix.Length ? null : dedupKey[(at + 1)..];
    }
}
