using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// Gathers what <see cref="HealthCheck"/> judges.
///
/// Every question here is asked of stored data rather than of a process. "Did
/// the collector run" is the wrong question - a run that finds an empty
/// mailbox, or authenticates against the wrong one, succeeds every time. "When
/// did a report last land" is the one that notices.
/// </summary>
public sealed class HealthService(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <param name="backupDirectory">
    /// Where backups should be. Null means nobody said, and nothing is
    /// concluded about them - an absent answer to a question never asked is
    /// not a finding.
    /// </param>
    public async Task<HealthFacts> GatherAsync(
        string? backupDirectory = null, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        var at = now ?? DateTimeOffset.UtcNow;

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        return new HealthFacts
        {
            Collection = await CollectionAsync(db, at, ct).ConfigureAwait(false),
            Quiet = await QuietAsync(db, at, ct).ConfigureAwait(false),
            HeldTwice = await HeldTwiceAsync(db, ct).ConfigureAwait(false),
            BackupDirectory = backupDirectory,
            LastBackup = backupDirectory is null ? null : NewestBackup(backupDirectory),
        };
    }

    /// <summary>One row per organization holding domains.</summary>
    private static async Task<IReadOnlyList<CollectionFacts>> CollectionAsync(
        SqliteConnection db, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = db.CreateCommand();

        // Correlated subqueries rather than joins, because joining domains and
        // reports together multiplies them: every report row comes back once
        // per domain the organization holds, and any SUM over it is then that
        // many times too big. Written as a join first, this reported "32,164
        // reports stored today" against a real database holding 1,892 - which
        // is 1,892 x 17 domains, and is exactly the shape of wrong that reads
        // as plausible.
        //
        // The domain count is the reason the organization is listed at all: an
        // organization with none is not collecting for anybody, so there is
        // nothing to say about its silence.
        command.CommandText = """
            SELECT t.slug,
                   (SELECT COUNT(*) FROM domains d
                     WHERE d.tenant_id = t.id AND d.is_active = 1 AND d.deleted_at IS NULL),
                   (SELECT MAX(r.ingested_at) FROM aggregate_reports r WHERE r.tenant_id = t.id),
                   (SELECT COUNT(*) FROM aggregate_reports r
                     WHERE r.tenant_id = t.id AND r.ingested_at >= $dayAgo)
            FROM tenants t
            WHERE t.deleted_at IS NULL
              AND EXISTS (SELECT 1 FROM domains d
                           WHERE d.tenant_id = t.id AND d.is_active = 1 AND d.deleted_at IS NULL)
            ORDER BY t.slug
            """;
        command.Parameters.AddWithValue("$dayAgo", Iso(now.AddDays(-1)));

        var found = new List<CollectionFacts>();

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            found.Add(new CollectionFacts(
                reader.GetString(0),
                reader.GetInt32(1),
                reader.IsDBNull(2) ? null : Parse(reader.GetString(2)),
                reader.IsDBNull(3) ? 0 : reader.GetInt32(3)));
        }

        return found;
    }

    /// <summary>
    /// Domains that had reports arriving and stopped.
    /// </summary>
    /// <remarks>
    /// Requires history. A domain nobody has ever collected for is an
    /// onboarding question rather than a domain that went quiet, and the two
    /// need different answers - conflating them would have every newly added
    /// domain raise an alarm on the day it was added.
    /// </remarks>
    private static async Task<IReadOnlyList<QuietDomain>> QuietAsync(
        SqliteConnection db, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.name, MAX(r.date_end), COUNT(r.id)
            FROM domains d
            JOIN aggregate_reports r ON r.domain_id = d.id
            WHERE d.is_active = 1 AND d.deleted_at IS NULL
            GROUP BY d.id, d.name
            HAVING MAX(r.date_end) < $cutoff
            ORDER BY MAX(r.date_end)
            """;
        command.Parameters.AddWithValue("$cutoff", Iso(now.AddDays(-HealthCheck.QuietAfterDays)));

        var found = new List<QuietDomain>();

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            found.Add(new QuietDomain(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : Parse(reader.GetString(1)),
                reader.GetInt32(2)));
        }

        return found;
    }

    /// <summary>Domain names more than one organization holds.</summary>
    private static async Task<IReadOnlyList<string>> HeldTwiceAsync(SqliteConnection db, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT name FROM domains
            WHERE deleted_at IS NULL
            GROUP BY name
            HAVING COUNT(DISTINCT tenant_id) > 1
            ORDER BY name
            """;

        var found = new List<string>();

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { found.Add(reader.GetString(0)); }

        return found;
    }

    /// <summary>
    /// When the newest backup in a directory was taken.
    /// </summary>
    /// <remarks>
    /// Read from the file NAME rather than its timestamp. A backup's whole
    /// purpose is to be copied somewhere else, and copying resets an mtime -
    /// so a directory synced from another machine would otherwise all look
    /// like it was taken at once, and a stale set would look fresh.
    /// </remarks>
    internal static DateTimeOffset? NewestBackup(string directory)
    {
        if (!Directory.Exists(directory)) { return null; }

        DateTimeOffset? newest = null;

        foreach (var path in Directory.EnumerateFiles(
                     directory, $"{BackupService.Prefix}*{BackupService.Extension}"))
        {
            var name = Path.GetFileNameWithoutExtension(path)[BackupService.Prefix.Length..];

            if (DateTimeOffset.TryParseExact(
                    name, "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var taken)
                && (newest is null || taken > newest))
            {
                newest = taken;
            }
        }

        return newest;
    }

    private static string Iso(DateTimeOffset when) =>
        when.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static DateTimeOffset? Parse(string stored) =>
        DateTime.TryParse(stored, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var when)
            ? new DateTimeOffset(when, TimeSpan.Zero)
            : null;
}
