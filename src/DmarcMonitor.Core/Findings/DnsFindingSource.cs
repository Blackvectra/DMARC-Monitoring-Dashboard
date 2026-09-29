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
            await _lifecycle.ObserveAsync(Observation(save, change, now), ct).ConfigureAwait(false);
            observed++;
        }

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
        Title = change.Summary,
        DedupKey = DedupKey(save.DomainId!, change.RecordType),
        EvidenceRef = change.EventId is null ? null : "drift:" + change.EventId,
        ExpectedRef = RecordRef(change.OldValue),
        PayloadJson = change.WasExpected ? """{"wasExpected":true}""" : null,
        At = now,
    };

    /// <summary>What each record says in this reading; a record not published is absent from the map.</summary>
    private static Dictionary<string, string> Current(PublishedRecords published, DnsCheckStatus status)
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
