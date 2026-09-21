using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Reporting;

/// <summary>What an export is written as.</summary>
public enum ExportFormat
{
    /// <summary>
    /// One JSON object per line.
    /// </summary>
    /// <remarks>
    /// The default, because it is what everything downstream already reads:
    /// OpenSearch's _bulk endpoint, jq, Splunk's HEC, a Kafka producer. A
    /// single JSON array would have to be held whole in memory at both ends,
    /// which for a year of a book of domains is the wrong shape.
    /// </remarks>
    Ndjson,

    /// <summary>For a spreadsheet, which is where a lot of real analysis happens.</summary>
    Csv,
}

/// <summary>Which rows to write.</summary>
public sealed record ExportQuery
{
    /// <summary>One organization by id, or null for every one.</summary>
    /// <remarks>
    /// What anything serving a signed-in person must set. The schema allows two
    /// organizations to each manage a domain of the same name, so a query that
    /// does not say which one answers with somebody else's mail.
    /// </remarks>
    public string? TenantId { get; init; }

    /// <summary>One organization by slug, which is what the command line has.</summary>
    public string? OrgSlug { get; init; }

    /// <summary>One client's domains, by slug, or null for all of them.</summary>
    public string? ClientSlug { get; init; }

    /// <summary>One domain, or null for all of them.</summary>
    public string? Domain { get; init; }

    /// <summary>How far back to go. Null for everything held.</summary>
    public int? Days { get; init; }

    /// <summary>Only the rows that did not pass DMARC.</summary>
    public bool FailuresOnly { get; init; }

    /// <summary>
    /// Start after this row id, for shipping only what is new.
    /// </summary>
    /// <remarks>
    /// The watermark. Rows are never rewritten once stored - a reporter
    /// resending a report is refused by the dedup key rather than merged - so
    /// "everything above the last id I shipped" is exactly the new mail, and an
    /// incremental run costs an index seek instead of a scan.
    /// </remarks>
    public long? AfterId { get; init; }
}

/// <summary>What an export wrote, and where to resume from.</summary>
/// <param name="Rows">How many rows were written.</param>
/// <param name="LastId">
/// The highest row id written, or the <see cref="ExportQuery.AfterId"/> it
/// started from when nothing matched. Pass it back as <c>AfterId</c> next time.
/// </param>
public readonly record struct ExportResult(long Rows, long LastId);

/// <summary>
/// Writes the stored aggregate records out, one row at a time.
///
/// The answer to the one thing a fixed set of screens genuinely cannot do.
/// "Every address that hit these three domains, aligned on SPF only, in a
/// six-hour window" is a query in a search index and a code change here - so
/// rather than grow a query language, this hands the rows over in a shape every
/// other tool already reads, and lets jq, a spreadsheet, OpenSearch or Splunk
/// be the query language.
///
/// It is also the shipper for running both: keep retention here aggressive and
/// let an index hold the long tail.
///
/// Streamed rather than gathered. A year of a book of domains is millions of
/// rows, and building that list in memory to hand back would be the wrong shape
/// at both ends.
/// </summary>
public sealed class ReportExporter(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>
    /// The columns, in order. Also the CSV header.
    /// </summary>
    /// <remarks>
    /// Enough to redo the alignment analysis somewhere else, which is the whole
    /// point: the evaluated result and the authentication result are separate
    /// columns because a valid signature over the wrong domain is a pass at
    /// authentication and a fail at alignment, and collapsing the two is what
    /// makes DMARC data read as a contradiction.
    /// </remarks>
    internal static readonly string[] Columns =
    [
        "id", "date_begin", "date_end",
        "organization", "client", "domain",
        "header_from", "envelope_from", "envelope_to", "is_subdomain",
        "source_ip", "messages",
        "dmarc_result", "disposition", "fail_reason", "override_reason",
        "dkim_aligned", "spf_aligned",
        "dkim_domain", "dkim_selector", "dkim_auth",
        "spf_domain", "spf_auth",
        "policy_p", "reporter", "report_id",
    ];

    /// <summary>Columns that must stay numbers rather than become strings.</summary>
    /// <remarks>
    /// An index infers its mapping from the first document it sees, and "10" is
    /// not a number. Getting this wrong is not a cosmetic problem: it is a
    /// field you then cannot sum, discovered a month of data later.
    /// </remarks>
    private static readonly HashSet<string> Numbers = ["id", "messages"];

    /// <summary>Columns stored as 0/1 that mean yes and no.</summary>
    private static readonly HashSet<string> Booleans = ["is_subdomain"];

    /// <summary>The characters that force a CSV field to be quoted.</summary>
    private static readonly System.Buffers.SearchValues<char> NeedsQuoting =
        System.Buffers.SearchValues.Create(",\"\n\r");

    private const string Sql = """
        SELECT r.id, r.date_begin, a.date_end,
               t.slug, c.slug, d.name,
               COALESCE(NULLIF(r.header_from, ''), d.name),
               r.envelope_from, r.envelope_to, r.is_subdomain,
               r.source_ip, r.message_count,
               r.dmarc_result, r.disposition, r.fail_reason, r.override_reason,
               r.dkim_result, r.spf_result,
               r.dkim_domain, r.dkim_selector, r.dkim_auth_result,
               r.spf_domain, r.spf_auth_result,
               a.policy_p, a.org_name, a.external_report_id
        FROM aggregate_records r
        JOIN domains d ON d.id = r.domain_id
        JOIN clients c ON c.id = r.client_id
        JOIN tenants t ON t.id = r.tenant_id
        JOIN aggregate_reports a ON a.id = r.report_id
        WHERE d.deleted_at IS NULL
          AND ($tenant  IS NULL OR r.tenant_id = $tenant)
          AND ($org     IS NULL OR t.slug = $org)
          AND ($client  IS NULL OR c.slug = $client)
          AND ($domain  IS NULL OR LOWER(d.name) = $domain)
          AND ($since   IS NULL OR r.date_begin >= $since)
          AND ($afterId IS NULL OR r.id > $afterId)
          AND ($failuresOnly = 0 OR r.dmarc_result <> 'pass')
        ORDER BY r.id
        """;

    /// <summary>
    /// Writes matching rows, and says how many and where to resume.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Ordered by row id rather than by date. Three reasons, and the last is
    /// the one that matters: id order is a total order so the output is
    /// reproducible; it is the primary key so a scan is already in it and no
    /// temporary sort is built, which is what would quietly turn a streamed
    /// export of a million rows back into a gathered one; and it is a watermark
    /// a caller can resume from.
    /// </para>
    /// <para>
    /// The writer is flushed but not closed: the caller owns it, and closing
    /// somebody else's stdout is the kind of thing that only shows up in a
    /// pipeline.
    /// </para>
    /// </remarks>
    public async Task<ExportResult> WriteAsync(
        ExportQuery query, TextWriter writer, ExportFormat format = ExportFormat.Ndjson,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(writer);

        if (format == ExportFormat.Csv)
        {
            await writer.WriteLineAsync(string.Join(',', Columns)).ConfigureAwait(false);
        }

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = Sql;

        command.Parameters.AddWithValue("$tenant", Or(query.TenantId));
        command.Parameters.AddWithValue("$org", Or(Lower(query.OrgSlug)));
        command.Parameters.AddWithValue("$client", Or(Lower(query.ClientSlug)));
        command.Parameters.AddWithValue("$domain", Or(Lower(query.Domain)));
        command.Parameters.AddWithValue("$afterId", Or(query.AfterId));
        command.Parameters.AddWithValue("$failuresOnly", query.FailuresOnly ? 1 : 0);
        command.Parameters.AddWithValue("$since", Or(Since(query.Days)));

        long written = 0;
        var lastId = query.AfterId ?? 0;

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();

            await writer
                .WriteLineAsync(format == ExportFormat.Csv ? CsvRow(reader) : JsonRow(reader))
                .ConfigureAwait(false);

            lastId = reader.GetInt64(0);
            written++;
        }

        await writer.FlushAsync(ct).ConfigureAwait(false);
        return new ExportResult(written, lastId);
    }

    /// <summary>The cutoff for a window in days, as the database stores dates.</summary>
    internal static string? Since(int? days) =>
        days is { } d
            ? DateTimeOffset.UtcNow.AddDays(-Math.Max(1, d))
                .UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            : null;

    /// <summary>
    /// One row as JSON.
    /// </summary>
    /// <remarks>
    /// Numbers stay numbers, 0/1 flags become true and false, and an absent
    /// value is null rather than an empty string - because the thing reading
    /// this infers a mapping from the first document it sees, and a field typed
    /// as text is one you cannot sum or filter on later.
    /// </remarks>
    private static string JsonRow(SqliteDataReader reader)
    {
        var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();

            for (var i = 0; i < Columns.Length; i++)
            {
                var name = Columns[i];

                if (reader.IsDBNull(i)) { json.WriteNull(name); continue; }

                if (Numbers.Contains(name)) { json.WriteNumber(name, reader.GetInt64(i)); continue; }
                if (Booleans.Contains(name)) { json.WriteBoolean(name, reader.GetInt64(i) != 0); continue; }

                json.WriteString(name, reader.GetString(i));
            }

            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string CsvRow(SqliteDataReader reader)
    {
        var row = new StringBuilder();

        for (var i = 0; i < Columns.Length; i++)
        {
            if (i > 0) { row.Append(','); }
            row.Append(Escape(reader.IsDBNull(i)
                ? ""
                : Convert.ToString(reader.GetValue(i), CultureInfo.InvariantCulture) ?? ""));
        }

        return row.ToString();
    }

    /// <summary>
    /// A CSV field, quoted when it has to be.
    /// </summary>
    /// <remarks>
    /// A leading =, +, - or @ is prefixed with a quote as well. A spreadsheet
    /// treats those as the start of a formula, and these rows carry strings
    /// from other people's mail - a header that begins "=cmd" is a real thing
    /// to open on somebody's laptop.
    /// </remarks>
    internal static string Escape(string value)
    {
        // A newline inside an unquoted field is the one that matters: it ends
        // the record early, and everything after it reads as a row of its own.

        var text = value ?? "";

        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@')
        {
            text = "'" + text;
        }

        if (!text.AsSpan().ContainsAny(NeedsQuoting)) { return text; }

        return $"\"{text.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    private static object Or(object? value) => value ?? DBNull.Value;

    private static string? Lower(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().TrimEnd('.').ToLowerInvariant();
}
