using System.Globalization;

namespace DmarcMonitor.Core.Findings;

/// <summary>
/// The one lifecycle every finding goes through, whichever engine raised it:
/// observed, seen again, lost sight of, gone, back; and what people decide
/// about it in the meantime.
/// </summary>
/// <remarks>
/// <para>
/// Two rules hold everything else up. A finding is identified by its source's
/// dedup key, so the same condition seen every night is one row whose
/// counters move, and a condition that returns after resolution reopens that
/// row rather than starting a new one. And resolution is evidence: only a
/// successful observation that does not show the condition counts towards
/// it, for as many observations as the type demands. A collector that failed
/// marks what it could not see as unknown, and clears nothing.
/// </para>
/// <para>
/// What a person decides is a separate state. Closing a finding takes it out
/// of the queue and leaves its source state exactly where the source put it;
/// an exception does the same for a while, with a reason, an approver, a
/// compensating control and a date somebody will look again.
/// </para>
/// </remarks>
public sealed class FindingLifecycle(
    string databasePath, TimeProvider? clock = null, IReadOnlyDictionary<string, FindingTypeDefinition>? types = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly IReadOnlyDictionary<string, FindingTypeDefinition> _types = types ?? FindingTypes.All;

    public FindingStore Store { get; } = new(databasePath);

    // ---- what a source does -------------------------------------------------------

    /// <summary>
    /// A source saw a condition. Creates the finding, or moves the one it
    /// already has: the counters always; the severity, type and title when
    /// they changed; the state, when the source had resolved it or lost it.
    /// </summary>
    public async Task<Observed> ObserveAsync(Observation observation, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var definition = Definition(observation.Type, observation.SourceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(observation.Title);
        ArgumentException.ThrowIfNullOrWhiteSpace(observation.DedupKey);
        if (FindingStore.Rank(observation.Severity) == 0 && !string.Equals(observation.Severity, "info", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Severity must be info, warning or critical, not '{observation.Severity}'.", nameof(observation));
        }

        var at = observation.At ?? _clock.GetUtcNow();
        var existing = await Store.FindAsync(observation.TenantId, observation.SourceId, observation.ClientId, observation.DedupKey, ct)
            .ConfigureAwait(false);

        if (existing is null)
        {
            var created = new Finding
            {
                Id = Guid.NewGuid().ToString(),
                TenantId = observation.TenantId,
                ClientId = observation.ClientId,
                DomainId = observation.DomainId,
                SourceId = observation.SourceId,
                Type = definition.Id,
                Rule = observation.Rule,
                Severity = observation.Severity,
                Title = observation.Title.Trim(),
                DedupKey = observation.DedupKey,
                EvidenceRef = observation.EvidenceRef,
                ExpectedRef = observation.ExpectedRef,
                RelatedFindingId = observation.RelatedFindingId,
                FirstObservedAt = at,
                LastObservedAt = at,
                PayloadJson = observation.PayloadJson,
                CreatedAt = at,
                UpdatedAt = at,
            };
            await Store.InsertAsync(created, ct).ConfigureAwait(false);
            await Store.AppendEventAsync(created, FindingEventKinds.Observed, observation.SourceId, at,
                toValue: SourceStates.Active, note: created.Title, ct: ct).ConfigureAwait(false);
            return new Observed(await ReloadAsync(created, ct).ConfigureAwait(false), ObserveOutcome.Created);
        }

        var outcome = ObserveOutcome.Unchanged;
        var updated = existing with
        {
            Rule = observation.Rule,
            Severity = observation.Severity,
            Type = definition.Id,
            Title = observation.Title.Trim(),
            EvidenceRef = observation.EvidenceRef ?? existing.EvidenceRef,
            ExpectedRef = existing.ExpectedRef ?? observation.ExpectedRef,
            RelatedFindingId = observation.RelatedFindingId ?? existing.RelatedFindingId,
            PayloadJson = observation.PayloadJson ?? existing.PayloadJson,
            LastObservedAt = at,
            ObservationCount = existing.ObservationCount + 1,
            AbsentCount = 0,
            UpdatedAt = at,
        };

        if (string.Equals(existing.SourceState, SourceStates.Resolved, StringComparison.Ordinal))
        {
            // Back after being gone: the same finding, with its history, and
            // a person has to look at it again.
            outcome = ObserveOutcome.Reopened;
            updated = updated with
            {
                SourceState = SourceStates.Active,
                AnalystState = AnalystStates.Unreviewed,
                SourceResolvedAt = null,
                ReopenedCount = existing.ReopenedCount + 1,
            };
            await Store.AppendEventAsync(updated, FindingEventKinds.Reopened, observation.SourceId, at,
                fromValue: SourceStates.Resolved, toValue: SourceStates.Active,
                note: existing.SourceResolvedAt is { } resolved
                    ? "Seen again, " + Days(at - resolved) + " after its source resolved it."
                    : "Seen again after its source resolved it.", ct: ct).ConfigureAwait(false);
        }
        else if (string.Equals(existing.SourceState, SourceStates.Unknown, StringComparison.Ordinal))
        {
            outcome = ObserveOutcome.KnownAgain;
            updated = updated with { SourceState = SourceStates.Active };
            await Store.AppendEventAsync(updated, FindingEventKinds.Observed, observation.SourceId, at,
                fromValue: SourceStates.Unknown, toValue: SourceStates.Active,
                note: "The source can see it again, and it is still there.", ct: ct).ConfigureAwait(false);
        }

        if (!string.Equals(existing.Severity, updated.Severity, StringComparison.Ordinal))
        {
            if (outcome == ObserveOutcome.Unchanged) { outcome = ObserveOutcome.Changed; }
            await Store.AppendEventAsync(updated, FindingEventKinds.SeverityChanged, observation.SourceId, at,
                fromValue: existing.Severity, toValue: updated.Severity, note: updated.Title, ct: ct).ConfigureAwait(false);
        }
        if (!string.Equals(existing.Type, updated.Type, StringComparison.Ordinal))
        {
            if (outcome == ObserveOutcome.Unchanged) { outcome = ObserveOutcome.Changed; }
            await Store.AppendEventAsync(updated, FindingEventKinds.TypeChanged, observation.SourceId, at,
                fromValue: existing.Type, toValue: updated.Type, note: updated.Title, ct: ct).ConfigureAwait(false);
        }

        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return new Observed(await ReloadAsync(updated, ct).ConfigureAwait(false), outcome);
    }

    /// <summary>
    /// A successful observation of the finding's scope did not show it. One
    /// step towards resolution; the type says how many steps there are.
    /// </summary>
    public async Task<Finding> AbsentAsync(Finding finding, DateTimeOffset? at = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (string.Equals(finding.SourceState, SourceStates.Resolved, StringComparison.Ordinal)) { return finding; }

        var when = at ?? _clock.GetUtcNow();
        var required = Definition(finding.Type, finding.SourceId).ResolveAfterAbsent;
        var absent = finding.AbsentCount + 1;
        var count = absent.ToString(CultureInfo.InvariantCulture) + " of " + required.ToString(CultureInfo.InvariantCulture);

        Finding updated;
        if (absent >= required)
        {
            updated = finding with
            {
                AbsentCount = absent,
                SourceState = SourceStates.Resolved,
                SourceResolvedAt = when,
                UpdatedAt = when,
            };
            await Store.AppendEventAsync(updated, FindingEventKinds.SourceResolved, finding.SourceId, when,
                fromValue: finding.SourceState, toValue: SourceStates.Resolved,
                note: "Not seen on " + count + " successful observations.", ct: ct).ConfigureAwait(false);
        }
        else
        {
            updated = finding with { AbsentCount = absent, SourceState = SourceStates.Active, UpdatedAt = when };
            await Store.AppendEventAsync(updated, FindingEventKinds.ObservationAbsent, finding.SourceId, when,
                fromValue: finding.SourceState, toValue: SourceStates.Active,
                note: "Not seen on " + count + " successful observations needed to resolve it.", ct: ct).ConfigureAwait(false);
        }

        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return await ReloadAsync(updated, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// An observation of a scope failed. Every finding the source has open
    /// there becomes unknown, and none is cleared: a broken collector is not
    /// a condition that went away.
    /// </summary>
    /// <returns>How many findings were marked.</returns>
    public async Task<int> MarkUnknownAsync(
        string tenantId, string clientId, string sourceId, string? domainId = null, string? error = null,
        DateTimeOffset? at = null, CancellationToken ct = default)
    {
        var when = at ?? _clock.GetUtcNow();
        var marked = 0;

        foreach (var finding in await Store.OpenForScopeAsync(tenantId, clientId, sourceId, domainId, ct).ConfigureAwait(false))
        {
            if (string.Equals(finding.SourceState, SourceStates.Unknown, StringComparison.Ordinal)) { continue; }

            var updated = finding with { SourceState = SourceStates.Unknown, UpdatedAt = when };
            await Store.AppendEventAsync(updated, FindingEventKinds.SourceUnknown, sourceId, when,
                fromValue: finding.SourceState, toValue: SourceStates.Unknown,
                note: string.IsNullOrWhiteSpace(error) ? "The observation failed; nothing is known." : "The observation failed: " + error.Trim(),
                ct: ct).ConfigureAwait(false);
            await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
            marked++;
        }

        return marked;
    }

    /// <summary>
    /// After a successful observation of a whole scope: every finding the
    /// source has open there that the observation did not show is absent.
    /// </summary>
    public async Task<FindingReconciliation> ReconcileAsync(
        string tenantId, string clientId, string sourceId, string? domainId, IReadOnlySet<string> observedDedupKeys,
        DateTimeOffset? at = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(observedDedupKeys);

        int absent = 0, resolved = 0;
        foreach (var finding in await Store.OpenForScopeAsync(tenantId, clientId, sourceId, domainId, ct).ConfigureAwait(false))
        {
            if (observedDedupKeys.Contains(finding.DedupKey)) { continue; }

            var after = await AbsentAsync(finding, at, ct).ConfigureAwait(false);
            absent++;
            if (string.Equals(after.SourceState, SourceStates.Resolved, StringComparison.Ordinal)) { resolved++; }
        }

        return new FindingReconciliation(absent, resolved);
    }

    // ---- what a person does -------------------------------------------------------

    /// <summary>Somebody has seen it: unreviewed becomes investigating. Returns null when out of scope.</summary>
    public async Task<Finding?> AcknowledgeAsync(
        string id, string actor, string? note = null, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        var finding = await Store.GetAsync(id, tenantId, clientSlug, ct).ConfigureAwait(false);
        if (finding is null) { return null; }

        var now = _clock.GetUtcNow();
        var updated = string.Equals(finding.AnalystState, AnalystStates.Unreviewed, StringComparison.Ordinal)
            ? finding with { AnalystState = AnalystStates.Investigating, UpdatedAt = now }
            : finding with { UpdatedAt = now };
        await Store.AppendEventAsync(updated, FindingEventKinds.Acknowledged, actor, now,
            fromValue: finding.AnalystState, toValue: updated.AnalystState, note: note, ct: ct).ConfigureAwait(false);
        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return await ReloadAsync(updated, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// A person's decision. It never touches the source's state: closing a
    /// finding whose source still sees it leaves the source seeing it.
    /// </summary>
    public async Task<Finding?> SetAnalystStateAsync(
        string id, string state, string actor, string? note = null, string? tenantId = null, string? clientSlug = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        if (!AnalystStates.IsKnown(state))
        {
            throw new ArgumentException($"'{state}' is not an analyst state; one of: {string.Join(", ", AnalystStates.All)}.", nameof(state));
        }

        var finding = await Store.GetAsync(id, tenantId, clientSlug, ct).ConfigureAwait(false);
        if (finding is null) { return null; }

        var now = _clock.GetUtcNow();
        var updated = finding with { AnalystState = state, UpdatedAt = now };
        await Store.AppendEventAsync(updated, FindingEventKinds.AnalystStateChanged, actor, now,
            fromValue: finding.AnalystState, toValue: state, note: note, ct: ct).ConfigureAwait(false);
        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return await ReloadAsync(updated, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Records an exception: the finding leaves the queue and its source
    /// carries on observing it. Refuses one without a reason, an approver, a
    /// compensating control or a review date, and one on a finding that
    /// already has one open.
    /// </summary>
    public async Task<Finding?> ExceptAsync(
        string id, ExceptionRequest request, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Reason);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Approver);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.CompensatingControl);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.By);

        var now = _clock.GetUtcNow();
        if (request.ReviewAt <= now)
        {
            throw new ArgumentException("An exception needs a review date in the future; one nobody is due to look at again is a finding that was deleted.", nameof(request));
        }
        if (request.ExpiresAt is { } expires && expires <= now)
        {
            throw new ArgumentException("An exception's expiry has to be in the future.", nameof(request));
        }

        var finding = await Store.GetAsync(id, tenantId, clientSlug, ct).ConfigureAwait(false);
        if (finding is null) { return null; }
        if (finding.OpenException is not null)
        {
            throw new InvalidOperationException("This finding already has an open exception; end it before recording another.");
        }

        var exception = new FindingExceptionRecord
        {
            Id = Guid.NewGuid().ToString(),
            TenantId = finding.TenantId,
            ClientId = finding.ClientId,
            FindingId = finding.Id,
            Reason = request.Reason.Trim(),
            Approver = request.Approver.Trim(),
            CompensatingControl = request.CompensatingControl.Trim(),
            ApprovedAt = now,
            ReviewAt = request.ReviewAt,
            ExpiresAt = request.ExpiresAt,
            CreatedBy = request.By.Trim(),
            CreatedAt = now,
        };
        await Store.InsertExceptionAsync(exception, ct).ConfigureAwait(false);

        var updated = finding with { AnalystState = AnalystStates.AcceptedRisk, UpdatedAt = now };
        await Store.AppendEventAsync(updated, FindingEventKinds.ExceptionApplied, request.By, now,
            fromValue: finding.AnalystState, toValue: AnalystStates.AcceptedRisk,
            note: exception.Reason + " Approved by " + exception.Approver + "; compensating control: " + exception.CompensatingControl
                + ". Review " + exception.ReviewAt.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
                + (exception.ExpiresAt is { } e ? "; expires " + e.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "") + ".",
            ct: ct).ConfigureAwait(false);
        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return await ReloadAsync(updated, ct).ConfigureAwait(false);
    }

    /// <summary>Withdraws a finding's open exception. Returns false when it has none.</summary>
    public async Task<bool> EndExceptionAsync(
        string id, string actor, string? note = null, string? tenantId = null, string? clientSlug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        var finding = await Store.GetAsync(id, tenantId, clientSlug, ct).ConfigureAwait(false);
        if (finding?.OpenException is not { } open) { return false; }

        var now = _clock.GetUtcNow();
        if (!await Store.EndExceptionAsync(open.Id, "withdrawn", now, ct).ConfigureAwait(false)) { return false; }

        var updated = finding with { AnalystState = AnalystStates.Unreviewed, UpdatedAt = now };
        await Store.AppendEventAsync(updated, FindingEventKinds.ExceptionEnded, actor, now,
            fromValue: finding.AnalystState, toValue: AnalystStates.Unreviewed, note: note, ct: ct).ConfigureAwait(false);
        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Ends every exception whose expiry has passed. A finding its source
    /// still sees is back in the queue by that alone; one the source has
    /// resolved stays resolved.
    /// </summary>
    /// <returns>How many expired.</returns>
    public async Task<int> ExpireExceptionsAsync(DateTimeOffset? now = null, CancellationToken ct = default)
    {
        var when = now ?? _clock.GetUtcNow();
        var expired = 0;

        foreach (var exception in await Store.ExpiredAsync(when, ct).ConfigureAwait(false))
        {
            if (!await Store.EndExceptionAsync(exception.Id, "expired", when, ct).ConfigureAwait(false)) { continue; }
            expired++;

            var finding = await Store.GetAsync(exception.FindingId, ct: ct).ConfigureAwait(false);
            if (finding is null) { continue; }

            var updated = finding with { AnalystState = AnalystStates.Unreviewed, UpdatedAt = when };
            await Store.AppendEventAsync(updated, FindingEventKinds.ExceptionExpired, "lifecycle", when,
                fromValue: finding.AnalystState, toValue: AnalystStates.Unreviewed,
                note: string.Equals(finding.SourceState, SourceStates.Resolved, StringComparison.Ordinal)
                    ? "The exception expired; the source had already resolved the finding."
                    : "The exception expired and the source still sees the finding, so it is back in the queue.",
                ct: ct).ConfigureAwait(false);
            await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        }

        return expired;
    }

    /// <summary>Moves a finding along the remediation chain, or off it with null.</summary>
    public async Task<Finding?> StageRemediationAsync(
        string id, string? stage, string actor, string? note = null, string? tenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        if (stage is not null && !RemediationStages.IsKnown(stage))
        {
            throw new ArgumentException($"'{stage}' is not a remediation stage; one of: {string.Join(", ", RemediationStages.All)}.", nameof(stage));
        }

        var finding = await Store.GetAsync(id, tenantId, ct: ct).ConfigureAwait(false);
        if (finding is null) { return null; }

        var now = _clock.GetUtcNow();
        var updated = finding with { RemediationStage = stage, UpdatedAt = now };
        await Store.AppendEventAsync(updated, FindingEventKinds.RemediationStaged, actor, now,
            fromValue: finding.RemediationStage, toValue: stage, note: note, ct: ct).ConfigureAwait(false);
        await Store.UpdateAsync(updated, ct).ConfigureAwait(false);
        return await ReloadAsync(updated, ct).ConfigureAwait(false);
    }

    // ---- helpers -------------------------------------------------------------------

    private FindingTypeDefinition Definition(string type, string sourceId)
    {
        if (!_types.TryGetValue(type, out var definition))
        {
            throw new ArgumentException($"No finding type '{type}' is defined; a type needs a source that says what identifies, evidences and resolves it.", nameof(type));
        }
        if (!string.Equals(definition.SourceId, sourceId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Finding type '{type}' belongs to source '{definition.SourceId}', not '{sourceId}'.", nameof(sourceId));
        }
        return definition;
    }

    private async Task<Finding> ReloadAsync(Finding finding, CancellationToken ct) =>
        await Store.GetAsync(finding.Id, ct: ct).ConfigureAwait(false) ?? finding;

    private static string Days(TimeSpan span)
    {
        var days = (int)Math.Round(span.TotalDays);
        return days == 1 ? "1 day" : days.ToString(CultureInfo.InvariantCulture) + " days";
    }
}
