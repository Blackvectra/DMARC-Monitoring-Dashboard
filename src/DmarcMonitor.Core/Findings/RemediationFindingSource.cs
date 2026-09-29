using System.Globalization;
using System.Text.Json;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Findings;

/// <summary>
/// A change this product applied, as a finding until it is known to have
/// taken. A DNS edit is not a remediation: the provider accepting it, DNS
/// serving it and the receivers behaving as intended are three different
/// facts, and this keeps them apart.
/// </summary>
/// <remarks>
/// <para>
/// The chain: applied, then DNS verification pending; a read that serves the
/// applied value verifies it; for a DMARC policy change the receivers' own
/// reports must then show the policy they applied for a period after the
/// change, which is the evidence a policy is in force; for a change with no
/// such evidence to wait for, DNS serving it is the end. Fourteen days after
/// DNS verification with no report covering the period, the finding resolves
/// as verified by DNS only, and says so: waiting forever is not a state.
/// </para>
/// <para>
/// The drift finding a change answers is told what the record should now
/// serve, so the two resolve on the same read; a rollback puts that back.
/// </para>
/// </remarks>
public sealed class RemediationFindingSource(string databasePath, TimeProvider? clock = null)
{
    /// <summary>How long a DMARC change waits for a receiver's report before DNS alone is accepted.</summary>
    public static readonly TimeSpan EffectivenessDeadline = TimeSpan.FromDays(14);

    /// <summary>How long DNS may take to serve an applied value before it is a warning.</summary>
    public static readonly TimeSpan SlowDns = TimeSpan.FromDays(1);

    private const string StillWaiting = "Awaiting DNS verification.";
    private const string Slow = "DNS does not serve it yet, a day on.";

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly FindingLifecycle _lifecycle = new(databasePath, clock);
    private readonly ClientDatabases _files = new(databasePath);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string DedupKey(string changeId) => "change:" + changeId;

    /// <summary>The record a change type edits, as drift findings name it; empty for one drift does not watch.</summary>
    public static string RecordTypeFor(string changeType) => changeType switch
    {
        ChangeType.DmarcPolicy => "dmarc",
        ChangeType.SpfIncludeRemove => "spf",
        ChangeType.MtaSts => "mta-sts",
        ChangeType.TlsRpt => "tls-rpt",
        _ => "",
    };

    /// <summary>Whether the receivers' reports can show a change of this type in force.</summary>
    public static bool HasEffectivenessEvidence(string changeType) => string.Equals(changeType, ChangeType.DmarcPolicy, StringComparison.Ordinal);

    private sealed record Payload(string ChangeType, string RecordType, string RecordName, DateTimeOffset AppliedAt, string AppliedBy);

    /// <summary>A change was written and recorded: the finding that waits for it to take.</summary>
    public async Task<Finding> AppliedAsync(
        string tenantId, string clientId, string domainId, string changeId, ChangePlan plan, string by, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(changeId);

        var now = _clock.GetUtcNow();
        var recordType = RecordTypeFor(plan.Type);
        var expected = DnsFindingSource.RecordRef(plan.ProposedValue);

        // The drift finding for the same record, if one is open: linked, and
        // told that what the record should serve now is what was applied.
        Finding? drift = null;
        if (recordType.Length > 0)
        {
            drift = await _lifecycle.Store.FindAsync(tenantId, FindingSourceIds.DnsScan, clientId, DnsFindingSource.DedupKey(domainId, recordType), ct)
                .ConfigureAwait(false);
            if (drift is not null && !string.Equals(drift.SourceState, SourceStates.Resolved, StringComparison.Ordinal))
            {
                await _lifecycle.SetExpectedAsync(drift.Id, expected, by,
                    "The record was changed from the Fix page; what it should serve now is what was applied (change " + changeId + ").",
                    ct: ct).ConfigureAwait(false);
            }
            else
            {
                drift = null;
            }
        }

        var observed = await _lifecycle.ObserveAsync(new Observation
        {
            TenantId = tenantId,
            ClientId = clientId,
            DomainId = domainId,
            SourceId = FindingSourceIds.Remediation,
            Type = FindingTypes.RemediationPendingVerification,
            Rule = plan.Type,
            Severity = "info",
            Title = "Applied: " + plan.Summary.TrimEnd('.') + ". " + StillWaiting,
            DedupKey = DedupKey(changeId),
            EvidenceRef = "change:" + changeId,
            ExpectedRef = expected,
            RelatedFindingId = drift?.Id,
            PayloadJson = JsonSerializer.Serialize(new Payload(plan.Type, recordType, plan.RecordName, now, by), Json),
            At = now,
        }, ct).ConfigureAwait(false);

        return await _lifecycle.StageRemediationAsync(observed.Finding.Id, RemediationStages.DnsPending, FindingSourceIds.Remediation,
            "Accepted by the DNS provider; not yet seen served.", ct: ct).ConfigureAwait(false) ?? observed.Finding;
    }

    /// <summary>
    /// A successful read of the domain: does DNS serve what was applied? The
    /// changes still waiting are seen again, and a warning a day on.
    /// </summary>
    /// <param name="current">What each record says in this reading, by record type.</param>
    /// <returns>How many pending changes the read touched.</returns>
    public async Task<int> ObserveDomainAsync(
        string tenantId, string clientId, string domainId, IReadOnlyDictionary<string, string> current, DateTimeOffset now,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(current);
        var touched = 0;

        foreach (var finding in await _lifecycle.Store.OpenForScopeAsync(tenantId, clientId, FindingSourceIds.Remediation, domainId, ct).ConfigureAwait(false))
        {
            if (!string.Equals(finding.RemediationStage, RemediationStages.DnsPending, StringComparison.Ordinal)) { continue; }
            touched++;

            var payload = PayloadOf(finding);
            if (payload is not null
                && string.Equals(DnsFindingSource.RecordRef(current.GetValueOrDefault(payload.RecordType)), finding.ExpectedRef, StringComparison.Ordinal))
            {
                await DnsVerifiedAsync(finding, payload, now, ct).ConfigureAwait(false);
                continue;
            }

            var slow = now - finding.FirstObservedAt > SlowDns;
            await _lifecycle.ObserveAsync(new Observation
            {
                TenantId = finding.TenantId,
                ClientId = finding.ClientId,
                DomainId = finding.DomainId,
                SourceId = FindingSourceIds.Remediation,
                Type = finding.Type,
                Rule = finding.Rule,
                Severity = slow ? "warning" : finding.Severity,
                Title = slow ? finding.Title.Replace(StillWaiting, Slow, StringComparison.Ordinal) : finding.Title,
                DedupKey = finding.DedupKey,
                At = now,
            }, ct).ConfigureAwait(false);
        }

        return touched;
    }

    /// <summary>
    /// What the domain's records are expected to serve because this product
    /// wrote it, by record type: the pending changes' values. A read serving
    /// one of these is the change arriving, not drift.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> ExpectedAsync(
        string tenantId, string clientId, string domainId, CancellationToken ct = default)
    {
        var expected = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var finding in await _lifecycle.Store.OpenForScopeAsync(tenantId, clientId, FindingSourceIds.Remediation, domainId, ct).ConfigureAwait(false))
        {
            if (!string.Equals(finding.RemediationStage, RemediationStages.DnsPending, StringComparison.Ordinal)) { continue; }
            if (finding.ExpectedRef is null || PayloadOf(finding) is not { } payload || payload.RecordType.Length == 0) { continue; }
            expected[payload.RecordType] = finding.ExpectedRef;
        }
        return expected;
    }

    /// <summary>The verify poll saw the value served. Returns false when there is no pending finding for the change.</summary>
    public async Task<bool> DnsVerifiedAsync(string changeId, DateTimeOffset? at = null, CancellationToken ct = default)
    {
        var finding = await _lifecycle.Store.FindBySourceKeyAsync(FindingSourceIds.Remediation, DedupKey(changeId), ct).ConfigureAwait(false);
        if (finding is null || string.Equals(finding.SourceState, SourceStates.Resolved, StringComparison.Ordinal)) { return false; }
        if (!string.Equals(finding.RemediationStage, RemediationStages.DnsPending, StringComparison.Ordinal)) { return false; }

        var payload = PayloadOf(finding);
        if (payload is null) { return false; }
        await DnsVerifiedAsync(finding, payload, at ?? _clock.GetUtcNow(), ct).ConfigureAwait(false);
        return true;
    }

    private async Task DnsVerifiedAsync(Finding finding, Payload payload, DateTimeOffset now, CancellationToken ct)
    {
        var verified = await _lifecycle.StageRemediationAsync(finding.Id, RemediationStages.DnsVerified, FindingSourceIds.Remediation,
            "DNS serves the applied value.", ct: ct).ConfigureAwait(false) ?? finding;

        if (HasEffectivenessEvidence(payload.ChangeType))
        {
            await _lifecycle.StageRemediationAsync(verified.Id, RemediationStages.EffectivenessPending, FindingSourceIds.Remediation,
                "Waiting for a receiver's report covering a period after the change to show the policy it applied.",
                title: Retitle(verified.Title, "DNS verified; awaiting a receiver's report."), ct: ct).ConfigureAwait(false);
            return;
        }

        await _lifecycle.ResolveBySourceAsync(verified,
            "Verified: DNS serves the applied value, and no runtime evidence applies to a change of this type.", now, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// For every change waiting on the receivers: has a report covering a
    /// period after the change shown the applied policy? Resolves the ones
    /// that have, and the ones fourteen days past DNS verification without
    /// one - as verified by DNS only, and saying so.
    /// </summary>
    /// <returns>How many findings were resolved.</returns>
    public async Task<int> CheckEffectivenessAsync(string? tenantId = null, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        var when = now ?? _clock.GetUtcNow();
        var resolved = 0;
        var pending = await _lifecycle.Store.ListAsync(new FindingFilter
        {
            TenantId = tenantId,
            Types = [FindingTypes.RemediationPendingVerification],
            SourceStates = [SourceStates.Active, SourceStates.Unknown],
            AwaitingVerificationOnly = true,
            Limit = 5000,
        }, ct).ConfigureAwait(false);

        foreach (var finding in pending)
        {
            if (!string.Equals(finding.RemediationStage, RemediationStages.EffectivenessPending, StringComparison.Ordinal)) { continue; }
            var payload = PayloadOf(finding);
            if (payload is null || finding.DomainId is null) { continue; }

            var change = await ChangeAsync(finding.ClientId, ChangeIdOf(finding), ct).ConfigureAwait(false);
            var applied = change?.NewValue is null ? null : DmarcRecord.Parse(change.NewValue);
            if (applied is not { IsValid: true }) { continue; }

            var evidence = await ReportShowingAsync(finding.ClientId, finding.DomainId, applied, payload.AppliedAt, ct).ConfigureAwait(false);
            if (evidence is { } seen)
            {
                await _lifecycle.ResolveBySourceAsync(finding,
                    "Verified: " + seen.Reporter + " reported applying p=" + applied.Policy + " for the period from "
                    + seen.From.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".", when, ct).ConfigureAwait(false);
                resolved++;
                continue;
            }

            var verifiedAt = await DnsVerifiedAtAsync(finding, ct).ConfigureAwait(false);
            if (verifiedAt is { } at && when - at > EffectivenessDeadline)
            {
                await _lifecycle.ResolveBySourceAsync(finding,
                    "Verified by DNS only: no receiver's report has covered a period after the change in "
                    + EffectivenessDeadline.TotalDays.ToString(CultureInfo.InvariantCulture) + " days.", when, ct).ConfigureAwait(false);
                resolved++;
            }
        }

        return resolved;
    }

    /// <summary>The change was rolled back: withdrawn, not verified, and the drift it answered expects what it did before.</summary>
    public async Task<bool> RolledBackAsync(string changeId, string by, string reason, CancellationToken ct = default)
    {
        var finding = await _lifecycle.Store.FindBySourceKeyAsync(FindingSourceIds.Remediation, DedupKey(changeId), ct).ConfigureAwait(false);
        if (finding is null) { return false; }

        var now = _clock.GetUtcNow();
        if (finding.RelatedFindingId is { } driftId)
        {
            var moved = (await _lifecycle.Store.EventsAsync(driftId, ct).ConfigureAwait(false))
                .LastOrDefault(e => e.Kind == FindingEventKinds.ExpectedChanged && e.Note is not null && e.Note.Contains(changeId, StringComparison.Ordinal));
            if (moved?.FromValue is { } before)
            {
                await _lifecycle.SetExpectedAsync(driftId, before, by, "Change " + changeId + " was rolled back; the record should serve what it did before it.", ct: ct)
                    .ConfigureAwait(false);
            }
        }

        if (string.Equals(finding.SourceState, SourceStates.Resolved, StringComparison.Ordinal)) { return false; }
        await _lifecycle.ResolveBySourceAsync(finding, "Rolled back by " + by.Trim() + ": " + reason.Trim() + ". The change is withdrawn, not verified.", now, ct)
            .ConfigureAwait(false);
        return true;
    }

    // ---- reading the evidence ----------------------------------------------------------

    private sealed record ReportEvidence(string Reporter, DateTimeOffset From);

    /// <summary>The first report of the domain covering a period after the change whose published policy is the applied one.</summary>
    private async Task<ReportEvidence?> ReportShowingAsync(string clientId, string domainId, DmarcRecord applied, DateTimeOffset appliedAt, CancellationToken ct)
    {
        await using var db = await _files.OpenAsync(ClientScope.Client(clientId), ["aggregate_reports"], ct: ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT org_name, date_begin, policy_p, policy_sp, policy_pct, policy_adkim, policy_aspf
            FROM aggregate_reports
            WHERE domain_id = $domain
            ORDER BY date_begin
            """;
        command.Parameters.AddWithValue("$domain", domainId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetValue(i).ToString();

            if (!DateTimeOffset.TryParse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var from)
                || from < appliedAt)
            {
                continue;
            }

            if (!Same(Text(2), applied.Policy)) { continue; }
            if (Text(3) is { } sp && !Same(sp, applied.EffectiveSubdomainPolicy)) { continue; }
            if (Text(4) is { } pct && int.TryParse(pct, NumberStyles.Integer, CultureInfo.InvariantCulture, out var percent) && percent != applied.Percent) { continue; }
            if (Text(5) is { } adkim && !Same(adkim, applied.StrictDkim ? "s" : "r")) { continue; }
            if (Text(6) is { } aspf && !Same(aspf, applied.StrictSpf ? "s" : "r")) { continue; }

            return new ReportEvidence(reader.GetString(0), from);
        }
        return null;
    }

    /// <summary>The change's row, from the file of the client whose domain it changed.</summary>
    private async Task<AppliedChange?> ChangeAsync(string clientId, string changeId, CancellationToken ct)
    {
        await using var db = await _files.OpenAsync(ClientScope.Client(clientId), ["dns_changes"], ct: ct).ConfigureAwait(false);
        return await RemediationService.GetChangeAsync(db, changeId, ct).ConfigureAwait(false);
    }

    private async Task<DateTimeOffset?> DnsVerifiedAtAsync(Finding finding, CancellationToken ct)
    {
        var staged = (await _lifecycle.Store.EventsAsync(finding.Id, ct).ConfigureAwait(false))
            .LastOrDefault(e => e.Kind == FindingEventKinds.RemediationStaged && e.ToValue == RemediationStages.DnsVerified);
        return staged?.At;
    }

    private static bool Same(string? a, string b) => a is not null && string.Equals(a.Trim(), b, StringComparison.OrdinalIgnoreCase);

    private static string ChangeIdOf(Finding finding) => finding.DedupKey["change:".Length..];

    private static Payload? PayloadOf(Finding finding)
    {
        if (finding.PayloadJson is null) { return null; }
        try { return JsonSerializer.Deserialize<Payload>(finding.PayloadJson, Json); }
        catch (JsonException) { return null; }
    }

    private static string Retitle(string title, string tail)
    {
        var at = title.IndexOf(". ", StringComparison.Ordinal);
        return (at < 0 ? title : title[..(at + 2)]) + tail;
    }
}
