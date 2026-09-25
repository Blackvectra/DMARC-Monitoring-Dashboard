using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// Removes report data past its retention window.
///
/// The only thing in this product that deletes a customer's history, so it is
/// built to be the opposite of a background tidy-up: it counts before it
/// deletes, it does nothing without being asked, it deletes each client's file
/// inside one transaction so a failure halfway leaves no file half-pruned, and
/// every run that removes anything writes a line to the audit log saying what
/// and under which policy.
///
/// Nothing here deletes a domain, a client or an organization. A customer who
/// sends no mail for a year still exists; only the reports age out.
/// </summary>
public sealed class RetentionService(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>
    /// Counts what is past the window without removing anything.
    /// </summary>
    /// <remarks>
    /// Its own method, and the default of the command that calls it. Somebody
    /// running this for the first time against a year of a customer's history
    /// should see the number before anything happens to it.
    /// </remarks>
    public Task<PruneResult> PreviewAsync(
        RetentionPolicy policy, DateTimeOffset now, CancellationToken ct = default) =>
        RunAsync(policy, now, apply: false, actor: null, audit: null, ct);

    /// <summary>
    /// Removes what is past the window.
    /// </summary>
    /// <param name="actor">Who asked. Goes in the audit log beside what was removed.</param>
    public Task<PruneResult> ApplyAsync(
        RetentionPolicy policy, DateTimeOffset now, string actor, AuditLog? audit = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        return RunAsync(policy, now, apply: true, actor, audit, ct);
    }

    private async Task<PruneResult> RunAsync(
        RetentionPolicy policy, DateTimeOffset now, bool apply, string? actor, AuditLog? audit,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // A policy that cannot be honoured is refused rather than clamped. The
        // clamp would silently keep more or less than the operator configured,
        // and this is the one operation where that is not a small difference.
        if (!policy.IsValid)
        {
            throw new ArgumentException(
                $"Retention policy is not usable: {string.Join("; ", policy.Problems)}", nameof(policy));
        }

        var aggregateCutoff = policy.AggregateCutoff(now);
        var forensicCutoff = policy.ForensicCutoff(now);

        // One client's file at a time: the reports are in each client's own
        // file, and each file is pruned in a transaction of its own. Counted
        // first, and counted the same way whether or not anything is then
        // removed, so the dry run and the real run cannot disagree.
        var files = new ClientDatabases(_databasePath);
        var result = new PruneResult(0, 0, 0, 0, apply);

        foreach (var client in await files.ListAsync(ct: ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(files.PathFor(client))) { continue; }

            await using var db = await files.OpenAsync(ClientScope.Client(client.Id), write: apply, ct: ct)
                .ConfigureAwait(false);

            var here = new PruneResult(
                await CountAsync(
                    db, "SELECT COUNT(*) FROM aggregate_reports WHERE date_end < $cutoff", aggregateCutoff, ct)
                    .ConfigureAwait(false),
                await CountAsync(
                    db,
                    "SELECT COUNT(*) FROM aggregate_records WHERE report_id IN "
                    + "(SELECT id FROM aggregate_reports WHERE date_end < $cutoff)",
                    aggregateCutoff, ct).ConfigureAwait(false),
                await CountAsync(
                    db, "SELECT COUNT(*) FROM forensic_reports WHERE received_at < $cutoff", forensicCutoff, ct)
                    .ConfigureAwait(false),
                await CountAsync(
                    db, "SELECT COUNT(*) FROM tls_reports WHERE date_end < $cutoff", aggregateCutoff, ct)
                    .ConfigureAwait(false),
                apply);

            result = new PruneResult(
                result.AggregateReports + here.AggregateReports,
                result.AggregateRecords + here.AggregateRecords,
                result.ForensicReports + here.ForensicReports,
                result.TlsReports + here.TlsReports,
                apply);

            if (!apply || here.NothingToDo) { continue; }

            await using var transaction = db.BeginTransaction(deferred: false);

            // Records before their reports, because the rows are the bulk and
            // a foreign key would otherwise decide the order for us on some
            // builds and not others.
            await ExecuteAsync(
                db, transaction,
                "DELETE FROM aggregate_records WHERE report_id IN "
                + "(SELECT id FROM aggregate_reports WHERE date_end < $cutoff)",
                aggregateCutoff, ct).ConfigureAwait(false);

            await ExecuteAsync(
                db, transaction, "DELETE FROM aggregate_reports WHERE date_end < $cutoff",
                aggregateCutoff, ct).ConfigureAwait(false);

            await ExecuteAsync(
                db, transaction, "DELETE FROM forensic_reports WHERE received_at < $cutoff",
                forensicCutoff, ct).ConfigureAwait(false);

            await ExecuteAsync(
                db, transaction, "DELETE FROM tls_reports WHERE date_end < $cutoff",
                aggregateCutoff, ct).ConfigureAwait(false);

            await transaction.CommitAsync(ct).ConfigureAwait(false);
        }

        if (!apply || result.NothingToDo) { return result with { Applied = apply && !result.NothingToDo }; }

        // After the commit, so the log never claims a deletion that rolled
        // back. Platform-wide rather than per-organization: one run covers
        // every tenant's data and splitting the entry would understate it.
        if (audit is not null)
        {
            await audit.RecordAsync(
                null, actor ?? "unknown", "retention.prune",
                $"{result.Describe()}; policy: {policy}", ct).ConfigureAwait(false);
        }

        return result;
    }

    private static async Task<int> CountAsync(
        SqliteConnection db, string sql, string cutoff, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$cutoff", cutoff);

        var value = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return value is long count ? (int)count : 0;
    }

    private static async Task ExecuteAsync(
        SqliteConnection db, SqliteTransaction transaction, string sql, string cutoff, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$cutoff", cutoff);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
