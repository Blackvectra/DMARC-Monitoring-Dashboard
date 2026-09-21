using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Rollout;

/// <summary>
/// What is currently published for a domain, as the reports describe it.
/// </summary>
/// <param name="Policy">p= as the newest report saw it.</param>
/// <param name="StrictDkim">adkim=s.</param>
/// <param name="StrictSpf">aspf=s.</param>
/// <param name="Percent">pct=.</param>
/// <param name="WindowDays">Days of reports the simulation is drawn from.</param>
public sealed record CurrentPolicy(
    string Policy, bool StrictDkim, bool StrictSpf, int Percent, int WindowDays);

/// <summary>
/// Loads the stored reports for one domain so a proposal can be replayed
/// against them.
///
/// Kept apart from <see cref="PolicySimulator"/>, which is pure and where every
/// rule worth arguing about lives. This only reads rows.
/// </summary>
public sealed class PolicySimulationService(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>
    /// Every row held for a domain inside the window, reduced to what DMARC
    /// evaluates.
    /// </summary>
    /// <remarks>
    /// Overridden failures are left in, unlike the domain page's source table.
    /// A forwarded message the receiver excused still failed, and a simulation
    /// that dropped it would understate what a stricter record costs - which
    /// is the direction that gets somebody's mail rejected.
    /// </remarks>
    public async Task<IReadOnlyList<AuthenticationFacts>> RowsAsync(
        string domain, int windowDays, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var rows = new List<AuthenticationFacts>();

        await using var db = new SqliteConnection(ReadOnly());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT COALESCE(NULLIF(r.header_from, ''), d.name),
                   r.dkim_domain, r.dkim_auth_result,
                   r.spf_domain,  r.spf_auth_result,
                   r.message_count, r.dmarc_result, r.source_ip
            FROM aggregate_records r
            JOIN domains d ON d.id = r.domain_id
            WHERE LOWER(d.name) = $domain
              AND d.is_active = 1 AND d.deleted_at IS NULL
              AND r.date_begin >= $since
            """;
        command.Parameters.AddWithValue("$domain", domain.Trim().TrimEnd('.').ToLowerInvariant());
        command.Parameters.AddWithValue("$since", Since(windowDays));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            rows.Add(new AuthenticationFacts
            {
                HeaderFrom = reader.GetString(0),
                DkimDomain = reader.IsDBNull(1) ? null : reader.GetString(1),
                DkimPassed = Passed(reader, 2),
                SpfDomain = reader.IsDBNull(3) ? null : reader.GetString(3),
                SpfPassed = Passed(reader, 4),
                Messages = reader.GetInt64(5),
                PassedAsEvaluated = string.Equals(
                    reader.IsDBNull(6) ? "" : reader.GetString(6), "pass", StringComparison.OrdinalIgnoreCase),
                SourceIp = reader.IsDBNull(7) ? "" : reader.GetString(7),
            });
        }

        return rows;
    }

    /// <summary>
    /// What the domain publishes today, so a proposal can be expressed as a
    /// change rather than as an absolute.
    /// </summary>
    /// <remarks>
    /// Read from the newest report rather than from DNS, deliberately: it has
    /// to describe the record that was in force over the mail being replayed.
    /// A record changed this morning would otherwise be compared against a
    /// month of mail it never governed.
    /// </remarks>
    public async Task<CurrentPolicy?> CurrentAsync(
        string domain, int windowDays, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        await using var db = new SqliteConnection(ReadOnly());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT a.policy_p, a.policy_adkim, a.policy_aspf, a.policy_pct,
                   CAST(julianday(MAX(a.date_end)) - julianday(MIN(a.date_begin)) AS INTEGER) + 1
            FROM aggregate_reports a
            JOIN domains d ON d.id = a.domain_id
            WHERE LOWER(d.name) = $domain AND a.date_begin >= $since
            GROUP BY a.domain_id
            ORDER BY MAX(a.date_end) DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$domain", domain.Trim().TrimEnd('.').ToLowerInvariant());
        command.Parameters.AddWithValue("$since", Since(windowDays));

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        return new CurrentPolicy(
            reader.IsDBNull(0) ? "none" : reader.GetString(0),
            Strict(reader, 1),
            Strict(reader, 2),
            reader.IsDBNull(3) ? 100 : reader.GetInt32(3),
            reader.IsDBNull(4) ? 0 : Math.Max(0, reader.GetInt32(4)));
    }

    private static bool Passed(SqliteDataReader reader, int column) =>
        !reader.IsDBNull(column)
        && string.Equals(reader.GetString(column), "pass", StringComparison.OrdinalIgnoreCase);

    private static bool Strict(SqliteDataReader reader, int column) =>
        !reader.IsDBNull(column)
        && reader.GetString(column).Trim().StartsWith('s');

    private static string Since(int windowDays) =>
        DateTimeOffset.UtcNow.AddDays(-Math.Max(1, windowDays))
            .UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private string ReadOnly() => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadOnly,
    }.ToString();
}
