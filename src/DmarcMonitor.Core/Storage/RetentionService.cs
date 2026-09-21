using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// Removes report data past its retention window.
///
/// The only thing in this product that deletes a customer's history, so it is
/// built to be the opposite of a background tidy-up: it counts before it
/// deletes, it does nothing without being asked, it deletes inside one
/// transaction so a failure halfway leaves nothing half-removed, and every run
/// that removes anything writes a line to the audit log saying what and under
/// which policy.
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

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = apply ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        // Counted first, and counted the same way whether or not anything is
        // then removed, so the dry run and the real run cannot disagree.
        var aggregateReports = await CountAsync(
            db, "SELECT COUNT(*) FROM aggregate_reports WHERE date_end < $cutoff", aggregateCutoff, ct)
            .ConfigureAwait(false);

        var aggregateRecords = await CountAsync(
            db,
            "SELECT COUNT(*) FROM aggregate_records WHERE report_id IN "
            + "(SELECT id FROM aggregate_reports WHERE date_end < $cutoff)",
            aggregateCutoff, ct).ConfigureAwait(false);

        var forensic = await CountAsync(
            db, "SELECT COUNT(*) FROM forensic_reports WHERE received_at < $cutoff", forensicCutoff, ct)
            .ConfigureAwait(false);

        var tls = await CountAsync(
            db, "SELECT COUNT(*) FROM tls_reports WHERE date_end < $cutoff", aggregateCutoff, ct)
            .ConfigureAwait(false);

        var result = new PruneResult(aggregateReports, aggregateRecords, forensic, tls, apply);

        if (!apply || result.NothingToDo) { return result with { Applied = apply && !result.NothingToDo }; }

        await using (var transaction = (SqliteTransaction)await db.BeginTransactionAsync(ct).ConfigureAwait(false))
        {
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
