using System.Text;
using System.Text.Json;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Handing the rows to something else, without lying about them on the way out.
///
/// Two things can go wrong here that are worse than a missing feature. A CSV
/// carrying a header from somebody else's mail can execute on the laptop it is
/// opened on, and NDJSON that types a count as text produces an index you
/// cannot sum a month of data later. Both are checked, along with the scoping,
/// because an export that crosses organizations hands one MSP's mail to
/// another in a file they will forward.
/// </summary>
public sealed class ReportExporterTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-export-{Guid.NewGuid():N}.db");

    public ReportExporterTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        SeedAsync().GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    /// <summary>
    /// Two organizations, one domain name each, and one row apiece.
    /// </summary>
    /// <remarks>
    /// The header_from on organization A's row starts with an equals sign on
    /// purpose. It is not a contrived value: header_from comes off other
    /// people's mail and nothing stops a sender putting whatever it likes
    /// there.
    /// </remarks>
    private async Task SeedAsync()
    {
        const string when = "2026-09-20 00:00:00";

        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        async Task Run(string sql)
        {
            await using var command = db.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        await Run($"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','Org A','{when}','{when}'),('t-b','orgb','Org B','{when}','{when}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','ca','Client A','{when}','{when}'),
                     ('c-b','t-b','cb','Client B','{when}','{when}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','example.com','{when}','{when}'),
                     ('d-b','t-b','c-b','example.com','{when}','{when}');
            """);

        await Run($"""
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,
               date_begin,date_end,raw_hash,received_at,ingested_at,policy_p)
              VALUES
                ('r-a','t-a','c-a','d-a','google.com','rep-a',
                 '2026-09-19 00:00:00','{when}','ha','{when}','{when}','reject'),
                ('r-b','t-b','c-b','d-b','google.com','rep-b',
                 '2026-09-19 00:00:00','{when}','hb','{when}','{when}','none');

            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,
               dmarc_result,disposition,dkim_result,spf_result,
               dkim_domain,dkim_selector,dkim_auth_result,spf_domain,spf_auth_result,
               header_from,envelope_from,is_subdomain)
              VALUES
                ('r-a','t-a','c-a','d-a','{when}','192.0.2.1',10,
                 'pass','none','pass','fail',
                 'example.com','sel1','pass','example.com','fail',
                 '=cmd|calc!A1','bounce@example.com',0),
                ('r-a','t-a','c-a','d-a','{when}','192.0.2.2',3,
                 'fail','quarantine','fail','fail',
                 NULL,NULL,'none','other.test','fail',
                 'a,b "quoted"','x@other.test',1),
                ('r-b','t-b','c-b','d-b','{when}','198.51.100.9',7,
                 'pass','none','pass','pass',
                 'example.com','orgb-sel','pass','example.com','pass',
                 'example.com','bounce@example.com',0);
            """);
    }

    private async Task<(string Text, ExportResult Result)> ExportAsync(
        ExportQuery query, ExportFormat format = ExportFormat.Ndjson)
    {
        var writer = new StringWriter();
        var result = await new ReportExporter(_dbPath).WriteAsync(query, writer, format);
        return (writer.ToString(), result);
    }

    private static List<JsonElement> Rows(string ndjson) =>
        [.. ndjson.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                  .Select(line => JsonDocument.Parse(line).RootElement)];

    // ---- scoping, which is the one that leaks --------------------------------

    [Fact]
    public async Task AnExportForOneOrganizationCannotSeeAnothers()
    {
        // The schema allows two organizations to each manage example.com, so a
        // query that does not say which one answers with somebody else's mail -
        // in a file the operator then sends to a customer.
        var (text, result) = await ExportAsync(new ExportQuery { TenantId = "t-a" });

        Assert.Equal(2, result.Rows);
        Assert.DoesNotContain("orgb-sel", text, StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.9", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSlugScopesItTheSameWayTheIdDoes()
    {
        // What the command line has to hand. It must not be a weaker door than
        // the id the web app passes.
        var (text, result) = await ExportAsync(new ExportQuery { OrgSlug = "OrgB" });

        Assert.Equal(1, result.Rows);
        Assert.Contains("orgb-sel", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoOrganizationMeansEveryOrganization()
    {
        // What an operator running this by hand wants, and what nothing serving
        // a signed-in person may ask for.
        var (_, result) = await ExportAsync(new ExportQuery());
        Assert.Equal(3, result.Rows);
    }

    // ---- the shape of what is written ----------------------------------------

    [Fact]
    public async Task ACountIsANumberAndAnAbsentValueIsNull()
    {
        // An index infers its mapping from the first document it sees. A count
        // written as "10" is a field nobody can sum, found out a month of data
        // later; an empty string for an absent DKIM domain is a value that
        // matches a search for one.
        var (text, _) = await ExportAsync(new ExportQuery { TenantId = "t-a" });
        var failing = Rows(text).Single(r => r.GetProperty("dmarc_result").GetString() == "fail");

        Assert.Equal(JsonValueKind.Number, failing.GetProperty("messages").ValueKind);
        Assert.Equal(3, failing.GetProperty("messages").GetInt32());
        Assert.Equal(JsonValueKind.Null, failing.GetProperty("dkim_domain").ValueKind);
        Assert.Equal(JsonValueKind.Null, failing.GetProperty("dkim_selector").ValueKind);
    }

    [Fact]
    public async Task AFlagIsTrueOrFalseRatherThanOneOrZero()
    {
        var (text, _) = await ExportAsync(new ExportQuery { TenantId = "t-a" });
        var rows = Rows(text);

        Assert.Contains(rows, r => r.GetProperty("is_subdomain").ValueKind == JsonValueKind.True);
        Assert.Contains(rows, r => r.GetProperty("is_subdomain").ValueKind == JsonValueKind.False);
    }

    [Fact]
    public async Task AlignmentAndAuthenticationAreSeparateColumns()
    {
        // A valid signature over the wrong domain passes authentication and
        // fails alignment. Collapsing the two is what makes DMARC data read as
        // a contradiction, and an export that did it would carry the confusion
        // into whatever is querying it.
        var (text, _) = await ExportAsync(new ExportQuery { TenantId = "t-a" });
        var passing = Rows(text).Single(r => r.GetProperty("dmarc_result").GetString() == "pass");

        Assert.Equal("fail", passing.GetProperty("spf_aligned").GetString());
        Assert.Equal("fail", passing.GetProperty("spf_auth").GetString());
        Assert.Equal("pass", passing.GetProperty("dkim_aligned").GetString());
        Assert.Equal("pass", passing.GetProperty("dkim_auth").GetString());
    }

    [Fact]
    public async Task EveryLineIsValidJsonOnItsOwn()
    {
        // The property that makes it NDJSON rather than JSON with newlines in
        // it. A field carrying a quote or a comma must not end the line.
        var (text, result) = await ExportAsync(new ExportQuery());

        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(result.Rows, lines.Length);
        foreach (var line in lines) { JsonDocument.Parse(line); }
    }

    // ---- CSV, which opens on somebody's laptop ---------------------------------

    [Fact]
    public void AFieldThatWouldBecomeAFormulaIsDefused()
    {
        // These rows carry strings from other people's mail. A header beginning
        // "=cmd" is a real thing to hand somebody as a spreadsheet.
        Assert.Equal("'=cmd|calc!A1", ReportExporter.Escape("=cmd|calc!A1"));
        Assert.Equal("'+1", ReportExporter.Escape("+1"));
        Assert.Equal("'-2+3", ReportExporter.Escape("-2+3"));
        Assert.Equal("'@SUM(A1)", ReportExporter.Escape("@SUM(A1)"));
    }

    [Fact]
    public void ADefusedFieldIsStillQuotedWhenItNeedsToBe()
    {
        // Both rules at once, and in the right order: the quote goes on first,
        // then the whole thing is wrapped because it holds a comma.
        Assert.Equal("\"'=a,b\"", ReportExporter.Escape("=a,b"));
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("", "")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("two\nlines", "\"two\nlines\"")]
    [InlineData("carriage\rreturn", "\"carriage\rreturn\"")]
    public void OrdinaryFieldsAreLeftAloneAndAwkwardOnesAreQuoted(string value, string expected)
    {
        // The newline is the one that matters: unquoted it ends the record, and
        // everything after it reads as a row of its own.
        Assert.Equal(expected, ReportExporter.Escape(value));
    }

    [Fact]
    public async Task TheCsvStartsWithAHeaderAndOneLinePerRow()
    {
        var (text, result) = await ExportAsync(new ExportQuery { TenantId = "t-a" }, ExportFormat.Csv);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(string.Join(',', ReportExporter.Columns), lines[0]);
        Assert.Equal(result.Rows + 1, lines.Length);
        Assert.Contains("'=cmd|calc!A1", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEmptyCsvStillCarriesItsHeader()
    {
        // Otherwise a zero-row export is an empty file, which every reader
        // treats as a different thing from a table with no rows in it.
        var (text, result) = await ExportAsync(
            new ExportQuery { Domain = "nothing.test" }, ExportFormat.Csv);

        Assert.Equal(0, result.Rows);
        Assert.Equal(string.Join(',', ReportExporter.Columns), text.Trim());
    }

    // ---- filters ---------------------------------------------------------------

    [Fact]
    public async Task FailuresOnlyLeavesOutThePassingMail()
    {
        var (text, result) = await ExportAsync(new ExportQuery { FailuresOnly = true });

        Assert.Equal(1, result.Rows);
        Assert.All(Rows(text), r => Assert.Equal("fail", r.GetProperty("dmarc_result").GetString()));
    }

    [Fact]
    public async Task AClientNarrowsItFurther()
    {
        var (_, mine) = await ExportAsync(new ExportQuery { ClientSlug = "ca" });
        var (_, theirs) = await ExportAsync(new ExportQuery { ClientSlug = "cb" });

        Assert.Equal(2, mine.Rows);
        Assert.Equal(1, theirs.Rows);
    }

    [Fact]
    public async Task ADomainThatIsNotThereWritesNothingRatherThanEverything()
    {
        // The failure that matters for a filter: a name nobody matches falling
        // back to no filter at all, and exporting the whole book.
        var (_, result) = await ExportAsync(new ExportQuery { Domain = "not-in-the-book.test" });
        Assert.Equal(0, result.Rows);
    }

    [Fact]
    public async Task ADomainIsMatchedWhateverItsCaseOrTrailingDot()
    {
        var (_, result) = await ExportAsync(new ExportQuery { Domain = "EXAMPLE.com." });
        Assert.Equal(3, result.Rows);
    }

    [Fact]
    public void AWindowIsCountedBackFromNowInTheFormatTheDatabaseStores()
    {
        // Compared as text against date_begin, so the format is the whole of
        // the correctness. Anything else silently matches nothing or matches
        // everything.
        var since = ReportExporter.Since(7);

        Assert.NotNull(since);
        Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", since);
        Assert.True(DateTime.Parse(since!, System.Globalization.CultureInfo.InvariantCulture)
                    < DateTime.UtcNow);
        Assert.Null(ReportExporter.Since(null));
    }

    // ---- the watermark ---------------------------------------------------------

    [Fact]
    public async Task TheSecondRunShipsOnlyWhatTheFirstOneDidNot()
    {
        // The whole of the incremental story. Getting this wrong does not fail
        // loudly - it re-ships the same month every night, or skips a row.
        var (_, first) = await ExportAsync(new ExportQuery { TenantId = "t-a" });
        var (text, second) = await ExportAsync(
            new ExportQuery { TenantId = "t-a", AfterId = first.LastId });

        Assert.Equal(2, first.Rows);
        Assert.Equal(0, second.Rows);
        Assert.Equal("", text);
    }

    [Fact]
    public async Task ARunThatMatchesNothingKeepsTheWatermarkItStartedFrom()
    {
        // Otherwise a quiet night resets it to zero and the next run ships the
        // whole database again.
        var (_, result) = await ExportAsync(new ExportQuery { AfterId = 9999 });

        Assert.Equal(0, result.Rows);
        Assert.Equal(9999, result.LastId);
    }

    [Fact]
    public async Task ResumingPartWayThroughPicksUpExactlyWhereItStopped()
    {
        var (all, _) = await ExportAsync(new ExportQuery());
        var ids = Rows(all).Select(r => r.GetProperty("id").GetInt64()).ToList();

        Assert.Equal(ids.OrderBy(id => id), ids);   // ordered by id, so it can be resumed at all

        var (rest, result) = await ExportAsync(new ExportQuery { AfterId = ids[0] });

        Assert.Equal(2, result.Rows);
        Assert.Equal(ids.Skip(1), Rows(rest).Select(r => r.GetProperty("id").GetInt64()));
        Assert.Equal(ids[^1], result.LastId);
    }

    // ---- the caller's stream ------------------------------------------------------

    [Fact]
    public async Task TheWriterIsLeftOpenForWhateverIsNext()
    {
        // This is meant to be the left-hand side of a pipe. Closing somebody
        // else's stdout only ever shows up there.
        var writer = new StringWriter();
        await new ReportExporter(_dbPath).WriteAsync(new ExportQuery(), writer);

        await writer.WriteLineAsync("still usable");
        Assert.EndsWith("still usable" + Environment.NewLine, writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ItReadsWithoutWritingAndWithoutCreating()
    {
        // Opened read-only, so an export can run against the live database
        // while the collector has it, and a typo in --db reports rather than
        // leaving an empty file behind.
        var missing = Path.Combine(Path.GetTempPath(), $"dmarc-absent-{Guid.NewGuid():N}.db");

        await Assert.ThrowsAsync<SqliteException>(
            () => new ReportExporter(missing).WriteAsync(new ExportQuery(), new StringWriter()));

        Assert.False(File.Exists(missing));
    }

    [Fact]
    public void ADatabasePathIsRequired()
    {
        Assert.Throws<ArgumentException>(() => new ReportExporter("  "));
    }

    [Fact]
    public async Task TheUtf8InAHeaderSurvivesTheRoundTrip()
    {
        // Written through a Utf8JsonWriter and read back as a string, which is
        // two chances to mangle anything that is not ASCII.
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText =
            "UPDATE aggregate_records SET header_from = 'pöst.example' WHERE source_ip = '192.0.2.1'";
        await command.ExecuteNonQueryAsync();

        var (text, _) = await ExportAsync(new ExportQuery { TenantId = "t-a" });

        Assert.Contains(Rows(text), r => r.GetProperty("header_from").GetString() == "pöst.example");
    }

    [Fact]
    public async Task CancellingStopsIt()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new ReportExporter(_dbPath)
                .WriteAsync(new ExportQuery(), new StringWriter(), ExportFormat.Ndjson, cts.Token));
    }

    [Fact]
    public void EveryColumnIsNamedOnceAndInLowerSnakeCase()
    {
        // The column list is also the CSV header and every JSON key. A repeat
        // would silently overwrite a field in the JSON object.
        Assert.Equal(ReportExporter.Columns.Length, ReportExporter.Columns.Distinct().Count());
        Assert.All(ReportExporter.Columns, c => Assert.Matches("^[a-z][a-z0-9_]*$", c));
    }

    [Fact]
    public async Task TheColumnListAndTheQueryStayInStep()
    {
        // They are written in two places and read positionally, so a column
        // added to one and not the other shifts every field after it - a
        // silently wrong export rather than an error.
        var (text, _) = await ExportAsync(new ExportQuery { TenantId = "t-a" });

        foreach (var row in Rows(text))
        {
            Assert.Equal(ReportExporter.Columns.Length, row.EnumerateObject().Count());
        }

        var csv = new StringWriter();
        await new ReportExporter(_dbPath)
            .WriteAsync(new ExportQuery { TenantId = "t-a" }, csv, ExportFormat.Csv);

        Assert.Equal(
            ReportExporter.Columns.Length,
            csv.ToString().Split('\n')[0].Split(',').Length);
    }

    [Fact]
    public async Task ADeletedDomainIsNotExported()
    {
        // Soft-deleted domains are hidden everywhere else. An export that
        // carried them would be the one place a customer's removed domain
        // reappears, in a file going somewhere else.
        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();

        await using var command = db.CreateCommand();
        command.CommandText = "UPDATE domains SET deleted_at = '2026-09-21 00:00:00' WHERE id = 'd-b'";
        await command.ExecuteNonQueryAsync();

        var (_, result) = await ExportAsync(new ExportQuery());
        Assert.Equal(2, result.Rows);
    }

    [Fact]
    public async Task NullsAreRefusedRatherThanTreatedAsEmpty()
    {
        var exporter = new ReportExporter(_dbPath);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => exporter.WriteAsync(null!, new StringWriter()));
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => exporter.WriteAsync(new ExportQuery(), null!));
    }

    [Fact]
    public async Task TheBytesOnTheWireAreUtf8WithoutAByteOrderMark()
    {
        // What a _bulk endpoint and jq both require. A StringWriter would never
        // show this, so it is written through a real stream.
        var path = Path.Combine(Path.GetTempPath(), $"dmarc-export-{Guid.NewGuid():N}.ndjson");

        try
        {
            await using (var stream = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                await new ReportExporter(_dbPath).WriteAsync(new ExportQuery(), stream);
            }

            var bytes = await File.ReadAllBytesAsync(path);
            Assert.NotEqual<byte[]>([0xEF, 0xBB, 0xBF], bytes[..3]);
            Assert.Equal('{', (char)bytes[0]);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
