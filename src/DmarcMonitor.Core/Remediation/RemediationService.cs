using System.Globalization;
using System.Text.Json;
using DmarcMonitor.Core.Dns;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Remediation;

/// <summary>What applying a plan came to.</summary>
public sealed record ApplyOutcome
{
    public required ChangePlan Plan { get; init; }

    /// <summary>The dns_change_plans row this run wrote or found.</summary>
    public string? PlanId { get; init; }

    /// <summary>The dns_changes row, when something was written.</summary>
    public string? ChangeId { get; init; }

    public bool DryRun { get; init; }
    public bool Applied { get; init; }

    /// <summary>What was live immediately before the write. The rollback target.</summary>
    public string? Snapshot { get; init; }

    public string Provider { get; init; } = "";
    public string Error { get; init; } = "";

    /// <summary>What an operator sees; the same sentence whether or not anything was written.</summary>
    public string Message { get; init; } = "";
}

/// <summary>One row of the audit trail, for the history page and the client report.</summary>
public sealed record AppliedChange(
    string Id,
    string? PlanId,
    string Domain,
    string ClientSlug,
    string RecordName,
    string RecordType,
    string? PreviousValue,
    string? NewValue,
    string Provider,
    DateTimeOffset AppliedAt,
    string? AppliedBy,
    string? Reason,
    bool IsPropagated,
    DateTimeOffset? RolledBackAt,
    string? RollbackReason);

/// <summary>
/// Applies plans, and keeps the record of having done so.
///
/// The guardrails, in the order they fire:
///
///   1. A plan that is not safe is refused. Its blockers exist because
///      publishing would break something, and there is deliberately no way
///      to override them from here.
///   2. A no-op plan writes nothing. Running a remediation twice must be
///      idempotent, not churn the zone.
///   3. Without confirm nothing is written. The default is a dry run that
///      returns exactly what would change, so a page can show a diff and a
///      person can decide.
///   4. The live value is read immediately before the write, and that is
///      what goes in previous_value. A plan made ten minutes ago may be
///      stale, and the snapshot is what rollback restores, so it has to be
///      what the zone actually held at the moment of writing.
///
/// Every plan is stored, applied or not: a refused plan is the finding an
/// operator acts on, and a dry run is the evidence that the product looked.
/// </summary>
public sealed class RemediationService(string databasePath, DnsLookup? lookup = null)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();

    // Its own resolver, with no cache. The page's shared lookup caches for
    // the record's TTL, which is exactly the window this polls across: one
    // "not yet" answer would be repeated from cache until the poll gave up.
    private readonly DnsLookup _lookup = lookup ?? new DnsLookup(new DnsClient.LookupClient(new DnsClient.LookupClientOptions
    {
        Timeout = TimeSpan.FromSeconds(5),
        Retries = 2,
        UseCache = false,
    }));

    /// <summary>Applies a plan, or shows what applying it would do.</summary>
    /// <param name="confirm">Required to write anything. Absent, this is a dry run.</param>
    /// <param name="appliedBy">Who is doing this, for the audit trail.</param>
    /// <param name="reason">Why, in a sentence. Goes on the client's report as the reason for the change.</param>
    public async Task<ApplyOutcome> ApplyAsync(
        ChangePlan plan, IDnsProvider provider, bool confirm, string appliedBy, string reason, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(provider);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var ids = await DomainIdsAsync(db, plan.Domain, ct).ConfigureAwait(false);

        // Stored first, whatever happens next. The domain has to be known to
        // store anything, and a domain reports have never arrived for is one
        // this has no evidence about, which is not one it should be writing
        // to on somebody's say-so.
        if (ids is null)
        {
            return new ApplyOutcome
            {
                Plan = plan,
                DryRun = !confirm,
                Provider = provider.Name,
                Error = $"{plan.Domain} is not in the database. Import its reports and file it under a client first.",
                Message = $"Not applied: {plan.Domain} is not a domain this has reports for.",
            };
        }

        var planId = await StorePlanAsync(db, ids.Value, plan, appliedBy, ct).ConfigureAwait(false);

        if (!plan.IsSafe)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, DryRun = !confirm, Provider = provider.Name,
                Error = string.Join(" ", plan.Blockers),
                Message = plan.Summary,
            };
        }

        if (plan.IsNoop)
        {
            await SetPlanStatusAsync(db, planId, "superseded", ct).ConfigureAwait(false);
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, DryRun = !confirm, Provider = provider.Name,
                Snapshot = plan.CurrentValue,
                Message = plan.Summary + " (nothing to write)",
            };
        }

        // The live value, from the provider rather than a resolver: a cached
        // answer would be exactly the stale value this step exists to avoid.
        string? live;
        try
        {
            var records = await provider.GetRecordsAsync(plan.RecordName, plan.RecordType, ct).ConfigureAwait(false);
            live = Matching(records, plan)?.Value;
        }
        catch (Exception ex) when (ex is HttpRequestException or DnsClient.DnsResponseException or TimeoutException or InvalidOperationException)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, DryRun = !confirm, Provider = provider.Name,
                Error = $"Could not read the current record before writing: {ex.Message}",
                Message = "Not applied: the current record could not be read, so there would be nothing to roll back to.",
            };
        }

        if (!confirm)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, DryRun = true, Provider = provider.Name,
                Snapshot = live,
                Message = $"Would {Lower(plan.Summary)}. Nothing written: re-run with confirmation to apply.",
            };
        }

        if (!provider.CanWrite)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Provider = provider.Name, Snapshot = live,
                Error = $"No DNS API is configured for {plan.Domain}.",
                Message = $"Not applied: no DNS API is configured for {plan.Domain}. Publish this yourself, then run again to record it: "
                        + $"{plan.RecordType} {plan.RecordName} = {plan.ProposedValue}",
            };
        }

        // The zone moved since the plan was made. Writing over a value the
        // plan never saw is how two people's changes become one wrong record.
        if (live is not null && plan.CurrentValue.Length > 0 && !string.Equals(live, plan.CurrentValue, StringComparison.Ordinal))
        {
            await SetPlanStatusAsync(db, planId, "superseded", ct).ConfigureAwait(false);
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Provider = provider.Name, Snapshot = live,
                Error = "The record changed after this plan was made.",
                Message = $"Not applied: {plan.RecordName} now holds \"{live}\", not the value the plan was built from. Plan again.",
            };
        }

        // The second read of the zone, and it was the only provider call on
        // this path with nothing around it. A transient failure here threw out
        // of the whole method and reached the operator as a stack trace under
        // "This is a bug". Nothing has been written at this point, so the
        // honest answer is simply that it was not applied.
        DnsProviderRecord? existing;
        try
        {
            var records0 = await provider.GetRecordsAsync(plan.RecordName, plan.RecordType, ct).ConfigureAwait(false);
            existing = Matching(records0, plan);
        }
        catch (Exception ex) when (ex is HttpRequestException or DnsClient.DnsResponseException or TimeoutException or InvalidOperationException)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Provider = provider.Name, Snapshot = live,
                Error = $"Could not re-read the record before writing: {ex.Message}",
                Message = "Not applied: the record could not be read immediately before the write.",
            };
        }

        var write = new DnsRecordWrite(
            plan.RecordName, plan.RecordType, plan.ProposedValue,
            ReplacesId: existing?.Id, ReplacesValue: existing?.Value);

        ProviderWrite result;
        try
        {
            result = await provider.SetRecordAsync(write, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException or InvalidOperationException)
        {
            // Deliberately NOT worded as "not applied". The Cloudflare
            // provider has no exception handling of its own, so a connection
            // dropped after the request left is indistinguishable here from
            // one that never arrived - and a timeout is the case where the
            // write most likely DID happen. Claiming nothing was written would
            // be the one answer that is certainly unsafe.
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Provider = provider.Name, Snapshot = live,
                Error = $"The write to {provider.Name} failed: {ex.Message}",
                Message = $"The write to {provider.Name} did not complete, and whether it reached the zone is unknown. "
                        + $"Check {plan.RecordName} before trying again. It held \"{live}\" beforehand.",
            };
        }

        if (!result.Success)
        {
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Provider = provider.Name, Snapshot = live,
                Error = result.Error,
                Message = $"Not applied: {result.Error}",
            };
        }

        string changeId;
        try
        {
            changeId = await StoreChangeAsync(db, ids.Value, planId, plan, live, provider.Name, result.Id, appliedBy, reason, ct)
                .ConfigureAwait(false);
            await SetPlanStatusAsync(db, planId, "applied", ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SqliteException or IOException)
        {
            // The customer's zone HAS been changed and the row that records it
            // could not be written - a locked or full database, most likely.
            // Rollback works from that row, so there is now no automatic way
            // back, and silence here would leave a change nobody can see in
            // the history or on the client's report. The previous value goes
            // in the message because it is the only place left holding it.
            return new ApplyOutcome
            {
                Plan = plan, PlanId = planId, Applied = true, Provider = provider.Name, Snapshot = live,
                Error = $"The change was made but could not be recorded: {ex.Message}",
                Message = $"WRITTEN, BUT NOT RECORDED. {plan.RecordName} now holds \"{plan.ProposedValue}\". "
                        + $"It held \"{live}\" before. There is no audit row, so this will not appear in the history "
                        + "or on the client's report, and it cannot be rolled back by this product. Put that value "
                        + "back by hand if it was not wanted.",
            };
        }

        return new ApplyOutcome
        {
            Plan = plan, PlanId = planId, ChangeId = changeId, Applied = true, Provider = provider.Name,
            Snapshot = live,
            Message = $"Applied: {Lower(plan.Summary)}. Accepted by {provider.Name}; not yet confirmed visible in DNS.",
        };
    }

    /// <summary>
    /// Confirms a change is actually visible in DNS, polling until it is or
    /// the timeout passes.
    /// </summary>
    /// <remarks>
    /// A successful API call means accepted, not served. Without this an
    /// operator marks a client remediated while their mail behaves exactly
    /// as it did, which is worse than not having applied the change.
    /// </remarks>
    public async Task<bool> VerifyAsync(string changeId, TimeSpan? timeout = null, TimeSpan? poll = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(changeId);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var change = await GetChangeAsync(db, changeId, ct).ConfigureAwait(false)
            ?? throw new ArgumentException($"No change with id {changeId}.", nameof(changeId));

        if (change.IsPropagated) { return true; }

        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromMinutes(2));
        var wait = poll ?? TimeSpan.FromSeconds(10);
        string? error = null;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var published = await _lookup.ReadAsync(change.Domain, ct).ConfigureAwait(false);
                var seen = change.RecordName.StartsWith("_dmarc.", StringComparison.Ordinal)
                    ? published.DmarcRecord
                    : published.SpfRecords.Count > 0 ? published.SpfRecords[0] : null;

                if (change.NewValue is not null && string.Equals(Normalise(seen), Normalise(change.NewValue), StringComparison.Ordinal))
                {
                    await ExecAsync(db, "UPDATE dns_changes SET is_propagated = 1, propagated_at = $now, propagation_error = NULL WHERE id = $id",
                        ct, ("$now", Iso(DateTimeOffset.UtcNow)), ("$id", changeId)).ConfigureAwait(false);
                    return true;
                }

                error = published.LookupFailed ? "the lookup failed" : $"DNS still serves \"{seen ?? "(nothing)"}\"";
            }
            catch (Exception ex) when (ex is DnsClient.DnsResponseException or TimeoutException)
            {
                error = ex.Message;
            }

            if (DateTimeOffset.UtcNow + wait > deadline) { break; }
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }

        await ExecAsync(db, "UPDATE dns_changes SET propagation_error = $err WHERE id = $id",
            ct, ("$err", error ?? "not seen"), ("$id", changeId)).ConfigureAwait(false);
        return false;
    }

    /// <summary>
    /// Puts back what was there before a change.
    /// </summary>
    /// <remarks>
    /// Restores the snapshot taken at write time, not the plan's idea of the
    /// old value. Refuses a change already rolled back, because writing the
    /// old value a second time over whatever came after it is a new change,
    /// not an undo.
    /// </remarks>
    public async Task<ApplyOutcome> RollBackAsync(string changeId, IDnsProvider provider, string by, string reason, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(changeId);
        ArgumentNullException.ThrowIfNull(provider);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        var change = await GetChangeAsync(db, changeId, ct).ConfigureAwait(false)
            ?? throw new ArgumentException($"No change with id {changeId}.", nameof(changeId));

        var plan = new ChangePlan
        {
            Domain = change.Domain,
            Type = ChangeType.DmarcPolicy,
            RecordName = change.RecordName,
            RecordType = change.RecordType,
            CurrentValue = change.NewValue ?? "",
            ProposedValue = change.PreviousValue ?? "",
            Summary = $"Roll back {change.RecordName} to \"{change.PreviousValue ?? "(nothing)"}\"",
        };

        if (change.RolledBackAt is not null)
        {
            return new ApplyOutcome
            {
                Plan = plan, ChangeId = changeId, Provider = provider.Name,
                Error = "Already rolled back.",
                Message = $"Not rolled back: this change was already rolled back on {change.RolledBackAt:yyyy-MM-dd}.",
            };
        }

        if (!provider.CanWrite)
        {
            return new ApplyOutcome
            {
                Plan = plan, ChangeId = changeId, Provider = provider.Name,
                Error = $"No DNS API is configured for {change.Domain}.",
                Message = $"Not rolled back: no DNS API is configured for {change.Domain}. Restore this yourself: "
                        + $"{change.RecordType} {change.RecordName} = {change.PreviousValue ?? "(remove the record)"}",
            };
        }

        var records = await provider.GetRecordsAsync(change.RecordName, change.RecordType, ct).ConfigureAwait(false);
        var current = records.FirstOrDefault(r => string.Equals(r.Value, change.NewValue, StringComparison.Ordinal));

        ProviderWrite result;
        if (change.PreviousValue is null)
        {
            // The change created the record. Undoing it removes it.
            result = current is null
                ? ProviderWrite.Failed($"The value this change wrote is no longer at {change.RecordName}. Somebody else has changed it since; look before touching it.")
                : await provider.RemoveRecordAsync(current, ct).ConfigureAwait(false);
        }
        else
        {
            result = current is null
                ? ProviderWrite.Failed($"The value this change wrote is no longer at {change.RecordName}. Somebody else has changed it since; look before touching it.")
                : await provider.SetRecordAsync(new DnsRecordWrite(change.RecordName, change.RecordType, change.PreviousValue,
                    ReplacesId: current.Id, ReplacesValue: current.Value), ct).ConfigureAwait(false);
        }

        if (!result.Success)
        {
            return new ApplyOutcome
            {
                Plan = plan, ChangeId = changeId, Provider = provider.Name,
                Error = result.Error,
                Message = $"Not rolled back: {result.Error}",
            };
        }

        var now = Iso(DateTimeOffset.UtcNow);
        await ExecAsync(db, "UPDATE dns_changes SET rolled_back_at = $now, rolled_back_by = $by, rollback_reason = $why WHERE id = $id",
            ct, ("$now", now), ("$by", by), ("$why", reason), ("$id", changeId)).ConfigureAwait(false);
        if (change.PlanId is not null)
        {
            await SetPlanStatusAsync(db, change.PlanId, "rolled_back", ct).ConfigureAwait(false);
        }

        return new ApplyOutcome
        {
            Plan = plan, ChangeId = changeId, Applied = true, Provider = provider.Name, Snapshot = change.NewValue,
            Message = $"Rolled back: {change.RecordName} is \"{change.PreviousValue ?? "(removed)"}\" again.",
        };
    }

    /// <summary>The audit trail, newest first. For one domain, or all of them.</summary>
    public async Task<IReadOnlyList<AppliedChange>> HistoryAsync(string? domain = null, int limit = 100, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = ChangeSelect + " WHERE ($domain IS NULL OR d.name = $domain) ORDER BY ch.applied_at DESC LIMIT $limit";
        command.Parameters.AddWithValue("$domain", (object?)domain?.Trim().ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", limit);

        var result = new List<AppliedChange>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { result.Add(ChangeRow(reader)); }
        return result;
    }

    public async Task<AppliedChange?> GetChangeAsync(string changeId, CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);
        return await GetChangeAsync(db, changeId, ct).ConfigureAwait(false);
    }

    // ---- storage ---------------------------------------------------------------

    private const string ChangeSelect = """
        SELECT ch.id, ch.plan_id, d.name, c.slug, ch.record_name, ch.record_type, ch.previous_value, ch.new_value,
               ch.provider, ch.applied_at, ch.applied_by, ch.reason, ch.is_propagated, ch.rolled_back_at, ch.rollback_reason
        FROM dns_changes ch
        JOIN domains d ON d.id = ch.domain_id
        JOIN clients c ON c.id = ch.client_id
        """;

    private static async Task<AppliedChange?> GetChangeAsync(SqliteConnection db, string changeId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = ChangeSelect + " WHERE ch.id = $id OR ch.id LIKE $prefix LIMIT 1";
        command.Parameters.AddWithValue("$id", changeId);
        // Ids are long; the first eight characters are what an operator
        // reads off a screen, and unique enough at this table's size.
        command.Parameters.AddWithValue("$prefix", changeId.Length >= 8 ? changeId + "%" : changeId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? ChangeRow(reader) : null;
    }

    private static AppliedChange ChangeRow(SqliteDataReader r) => new(
        r.GetString(0),
        r.IsDBNull(1) ? null : r.GetString(1),
        r.GetString(2),
        r.GetString(3),
        r.GetString(4),
        r.GetString(5),
        r.IsDBNull(6) ? null : r.GetString(6),
        r.IsDBNull(7) ? null : r.GetString(7),
        r.GetString(8),
        When(r.GetString(9)) ?? DateTimeOffset.MinValue,
        r.IsDBNull(10) ? null : r.GetString(10),
        r.IsDBNull(11) ? null : r.GetString(11),
        r.GetInt64(12) == 1,
        r.IsDBNull(13) ? null : When(r.GetString(13)),
        r.IsDBNull(14) ? null : r.GetString(14));

    private static async Task<string> StorePlanAsync(SqliteConnection db, DomainIds ids, ChangePlan plan, string by, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        await ExecAsync(db, """
            INSERT INTO dns_change_plans
                (id, tenant_id, client_id, domain_id, change_type, record_name, record_type, current_value, proposed_value,
                 is_safe, is_noop, blockers_json, warnings_json, lookups_before, lookups_after, summary, status, created_at, created_by)
            VALUES ($id, $tenant, $client, $domain, $type, $name, $rtype, $current, $proposed,
                    $safe, $noop, $blockers, $warnings, $before, $after, $summary, $status, $now, $by)
            """, ct,
            ("$id", id), ("$tenant", ids.TenantId), ("$client", ids.ClientId), ("$domain", ids.DomainId),
            ("$type", plan.Type), ("$name", plan.RecordName), ("$rtype", plan.RecordType),
            ("$current", plan.CurrentValue), ("$proposed", plan.ProposedValue),
            ("$safe", plan.IsSafe ? 1 : 0), ("$noop", plan.IsNoop ? 1 : 0),
            ("$blockers", JsonSerializer.Serialize(plan.Blockers)), ("$warnings", JsonSerializer.Serialize(plan.Warnings)),
            ("$before", (object?)plan.LookupsBefore ?? DBNull.Value), ("$after", (object?)plan.LookupsAfter ?? DBNull.Value),
            ("$summary", plan.Summary), ("$status", plan.IsSafe ? "proposed" : "refused"),
            ("$now", Iso(DateTimeOffset.UtcNow)), ("$by", by)).ConfigureAwait(false);
        return id;
    }

    private static Task SetPlanStatusAsync(SqliteConnection db, string planId, string status, CancellationToken ct) =>
        ExecAsync(db, "UPDATE dns_change_plans SET status = $status WHERE id = $id", ct, ("$status", status), ("$id", planId));

    private static async Task<string> StoreChangeAsync(
        SqliteConnection db, DomainIds ids, string planId, ChangePlan plan, string? previous,
        string provider, string providerRecordId, string by, string reason, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        await ExecAsync(db, """
            INSERT INTO dns_changes
                (id, plan_id, tenant_id, client_id, domain_id, record_name, record_type, previous_value, new_value,
                 provider, provider_record_id, applied_at, applied_by, reason, is_propagated)
            VALUES ($id, $plan, $tenant, $client, $domain, $name, $rtype, $previous, $new,
                    $provider, $prid, $now, $by, $reason, 0)
            """, ct,
            ("$id", id), ("$plan", planId), ("$tenant", ids.TenantId), ("$client", ids.ClientId), ("$domain", ids.DomainId),
            ("$name", plan.RecordName), ("$rtype", plan.RecordType),
            ("$previous", (object?)previous ?? DBNull.Value), ("$new", plan.ProposedValue),
            ("$provider", provider), ("$prid", providerRecordId), ("$now", Iso(DateTimeOffset.UtcNow)),
            ("$by", by), ("$reason", reason)).ConfigureAwait(false);
        return id;
    }

    private readonly record struct DomainIds(string TenantId, string ClientId, string DomainId);

    private static async Task<DomainIds?> DomainIdsAsync(SqliteConnection db, string domain, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT tenant_id, client_id, id FROM domains WHERE name = $name AND deleted_at IS NULL LIMIT 1";
        command.Parameters.AddWithValue("$name", domain.Trim().TrimEnd('.').ToLowerInvariant());

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }
        return new DomainIds(reader.GetString(0), reader.GetString(1), reader.GetString(2));
    }

    /// <summary>
    /// The one record at a name this plan is about.
    /// </summary>
    /// <remarks>
    /// An apex holds many TXT records and a plan touches exactly one of them.
    /// Matched by the value the plan was built from first, and by the record
    /// kind (v=spf1, v=DMARC1) when the plan is creating one, so a write
    /// never lands on a verification token that happens to share the name.
    /// </remarks>
    private static DnsProviderRecord? Matching(IReadOnlyList<DnsProviderRecord> records, ChangePlan plan)
    {
        if (plan.CurrentValue.Length > 0)
        {
            var exact = records.FirstOrDefault(r => string.Equals(r.Value, plan.CurrentValue, StringComparison.Ordinal));
            if (exact is not null) { return exact; }
        }

        var prefix = plan.Type == ChangeType.SpfIncludeRemove ? "v=spf1" : "v=DMARC1";
        return records.FirstOrDefault(r => r.Value.TrimStart().StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static string Normalise(string? record) =>
        string.Join(' ', (record ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)).Trim();

    private static string Lower(string sentence) =>
        sentence.Length > 0 ? char.ToLowerInvariant(sentence[0]) + sentence[1..] : sentence;

    private static async Task ExecAsync(SqliteConnection db, string sql, CancellationToken ct, params (string, object)[] parameters)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) { command.Parameters.AddWithValue(name, value); }
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static DateTimeOffset? When(string text) =>
        DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
            ? new DateTimeOffset(d, TimeSpan.Zero)
            : null;
}
