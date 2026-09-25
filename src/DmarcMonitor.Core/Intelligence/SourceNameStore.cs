using System.Globalization;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Intelligence;

/// <summary>What an address reverses to, remembered between runs.</summary>
/// <param name="Ip">The address, as the reports carry it.</param>
/// <param name="ReverseName">The PTR, or null for "asked, and there is none".</param>
/// <param name="CheckedAt">When it was last asked.</param>
/// <param name="Answered">Whether the reverse zone answered at all.</param>
/// <param name="ForwardConfirmed">
/// Whether the name's own forward records point back at the address: null
/// until checked. See <see cref="Dns.DnsLookup.ForwardConfirmsAsync"/>.
/// </param>
public sealed record SourceName(
    string Ip, string? ReverseName, DateTimeOffset CheckedAt, bool Answered, bool? ForwardConfirmed = null)
{
    /// <summary>
    /// The source as it should be written down: a vendor's name if the
    /// catalogue knows it and the name is confirmed, else the reverse name as
    /// the address claims it, else the address itself.
    /// </summary>
    /// <remarks>
    /// Never empty, and never a lie. An address nobody can name is printed as
    /// an address, which is exactly what the table did before any of this
    /// existed - so the worst case is what used to be the only case. And an
    /// unconfirmed name is printed as the hostname it claims rather than as
    /// "INKY": the hostname is what the address says about itself, the vendor
    /// name would be this product vouching for it.
    /// </remarks>
    public string Display =>
        ForwardConfirmed == true && SourceCatalog.Identify(ReverseName) is { } known ? known.Name
        : !string.IsNullOrWhiteSpace(ReverseName) ? ReverseName
        : Ip;

    /// <summary>Whether anything better than the address is known.</summary>
    public bool IsNamed => Display != Ip;
}

/// <summary>
/// The reverse-name cache: read on every page that lists sources, written by
/// the nightly DNS pass.
/// </summary>
/// <remarks>
/// <para>
/// Reading and resolving are deliberately different jobs. A page that
/// resolved as it rendered would make one DNS query per row, on the thread
/// serving the request, against addresses chosen by whoever sent the reports
/// - which is slow on a good day and a way to make the application wait on
/// somebody else's broken reverse zone on a bad one. So pages read what is
/// already here and print the address for anything that is not.
/// </para>
/// <para>
/// Names appear progressively. A source seen for the first time this morning
/// is an address until the nightly pass reaches it, and that is the right
/// trade: the alternative is a page that hangs.
/// </para>
/// </remarks>
public sealed class SourceNameStore(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        ForeignKeys = true,
    }.ToString();

    /// <summary>
    /// The names known for these addresses. Addresses with no row are simply
    /// absent from the result.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, SourceName>> GetAsync(
        IEnumerable<string> addresses, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        var wanted = addresses
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .Select(a => a.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var found = new Dictionary<string, SourceName>(StringComparer.OrdinalIgnoreCase);
        if (wanted.Count == 0) { return found; }

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        // Chunked rather than one statement per address, and rather than one
        // enormous IN list. SQLite's default parameter limit is 999, and a
        // busy estate has more sources than that.
        foreach (var chunk in wanted.Chunk(500))
        {
            await using var command = db.CreateCommand();
            var names = new List<string>(chunk.Length);

            for (var i = 0; i < chunk.Length; i++)
            {
                names.Add($"$p{i}");
                command.Parameters.AddWithValue($"$p{i}", chunk[i]);
            }

            command.CommandText =
                $"SELECT ip, reverse_name, checked_at, answered, forward_confirmed FROM source_names WHERE ip IN ({string.Join(",", names)})";

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                var row = Read(reader);
                found[row.Ip] = row;
            }
        }

        return found;
    }

    /// <summary>Records what an address reverses to, replacing any earlier answer.</summary>
    /// <param name="forwardConfirmed">
    /// Whether the name points back at the address; null when that was not
    /// checked, which leaves the name to decide nothing until it is.
    /// </param>
    public async Task SaveAsync(
        string ip, string? reverseName, bool answered, DateTimeOffset? checkedAt = null,
        bool? forwardConfirmed = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO source_names (ip, reverse_name, checked_at, answered, forward_confirmed)
            VALUES ($ip, $name, $at, $answered, $confirmed)
            ON CONFLICT(ip) DO UPDATE SET
                reverse_name      = excluded.reverse_name,
                checked_at        = excluded.checked_at,
                answered          = excluded.answered,
                forward_confirmed = excluded.forward_confirmed
            """;

        command.Parameters.AddWithValue("$ip", ip.Trim());
        command.Parameters.AddWithValue(
            "$name", string.IsNullOrWhiteSpace(reverseName) ? DBNull.Value : reverseName.Trim().TrimEnd('.').ToLowerInvariant());
        command.Parameters.AddWithValue("$at", Iso(checkedAt ?? DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$answered", answered ? 1 : 0);
        command.Parameters.AddWithValue(
            "$confirmed",
            string.IsNullOrWhiteSpace(reverseName) || forwardConfirmed is null ? DBNull.Value : forwardConfirmed.Value ? 1 : 0);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Addresses seen in reports that nothing has looked up lately, worst
    /// first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Ordered by how many messages the address accounts for, so a run that
    /// is cut short by <paramref name="limit"/> has still named the sources
    /// somebody is actually looking at. A single message from an address
    /// nobody will ever scroll to can wait for tomorrow.
    /// </para>
    /// <para>
    /// An address whose reverse zone did not answer comes back sooner than one
    /// that answered "no such name": the first is a failure worth retrying,
    /// the second is a fact that rarely changes.
    /// </para>
    /// <para>
    /// A name stored before forward confirmation existed is due at once. Until
    /// it is checked it can decide nothing, so a source that used to be
    /// recognized as a mail filter would be judged without its name.
    /// </para>
    /// </remarks>
    public async Task<IReadOnlyList<string>> NeedingLookupAsync(
        int limit = 500,
        TimeSpan? maxAge = null,
        TimeSpan? retryAfter = null,
        CancellationToken ct = default)
    {
        var age = maxAge ?? TimeSpan.FromDays(30);
        var retry = retryAfter ?? TimeSpan.FromDays(1);

        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT r.source_ip
            FROM aggregate_records r
            LEFT JOIN source_names n ON n.ip = r.source_ip
            WHERE n.ip IS NULL
               OR (n.answered = 1 AND n.checked_at < $stale)
               OR (n.answered = 0 AND n.checked_at < $retry)
               OR (n.reverse_name IS NOT NULL AND n.forward_confirmed IS NULL)
            GROUP BY r.source_ip
            ORDER BY SUM(r.message_count) DESC
            LIMIT $limit
            """;

        command.Parameters.AddWithValue("$stale", Iso(DateTimeOffset.UtcNow - age));
        command.Parameters.AddWithValue("$retry", Iso(DateTimeOffset.UtcNow - retry));
        command.Parameters.AddWithValue("$limit", limit);

        var result = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add(reader.GetString(0));
        }

        return result;
    }

    /// <summary>How many addresses have a name, out of how many are known at all.</summary>
    public async Task<(int Named, int Total)> CoverageAsync(CancellationToken ct = default)
    {
        await using var db = new SqliteConnection(_connectionString);
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM source_names WHERE reverse_name IS NOT NULL),
                (SELECT COUNT(DISTINCT source_ip) FROM aggregate_records)
            """;

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false)
            ? (reader.GetInt32(0), reader.GetInt32(1))
            : (0, 0);
    }

    private static SourceName Read(SqliteDataReader r) => new(
        r.GetString(0),
        r.IsDBNull(1) ? null : r.GetString(1),
        DateTimeOffset.TryParse(
            r.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var at) ? at : DateTimeOffset.MinValue,
        r.GetInt32(3) != 0,
        r.IsDBNull(4) ? null : r.GetInt32(4) != 0);

    private static string Iso(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
}
