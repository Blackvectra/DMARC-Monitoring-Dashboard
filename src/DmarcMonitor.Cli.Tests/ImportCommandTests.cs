using System.IO.Compression;
using System.Text;
using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// <c>dmarc import --from &lt;folder&gt;</c>, run the way somebody runs it.
///
/// One zip with a damaged list of contents ended the whole import: the
/// exception came out of the extraction uncaught, the files after it in the
/// folder were never read, and the command reported it as a bug. And a run in
/// which some files did not import has to say which, and how many, and exit
/// non-zero - otherwise a script, or a scheduled task, is told it worked.
/// </summary>
public sealed class ImportCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-import-command-{Guid.NewGuid():N}");
    private readonly string _db;

    public ImportCommandTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "dmarc.db");
        new ReportStore(_db).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    /// <summary>A made-up aggregate report for a domain kept for examples.</summary>
    private static byte[] Report(string reportId) => Encoding.UTF8.GetBytes($"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>receiver.example</org_name>
            <report_id>{reportId}</report_id>
            <date_range><begin>1757894400</begin><end>1757980799</end></date_range>
          </report_metadata>
          <policy_published><domain>example.org</domain><p>none</p><pct>100</pct></policy_published>
          <record>
            <row><source_ip>192.0.2.25</source_ip><count>5</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
            <identifiers><header_from>example.org</header_from></identifiers>
            <auth_results><dkim><domain>example.org</domain><result>pass</result></dkim><spf><domain>example.org</domain><result>pass</result></spf></auth_results>
          </record>
        </feedback>
        """);

    private static byte[] Gzip(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true)) { gz.Write(content); }
        return ms.ToArray();
    }

    /// <summary>A zip that opens, then throws the moment its entries are read.</summary>
    private static byte[] DamagedZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = zip.CreateEntry("r.xml").Open();
            s.Write(Report("r-damaged"));
        }

        var bytes = ms.ToArray();
        var at = bytes.AsSpan().IndexOf([(byte)0x50, (byte)0x4B, (byte)0x01, (byte)0x02]);
        bytes[at + 2] = 0x09;
        return bytes;
    }

    private string Folder(params (string Name, byte[] Content)[] files)
    {
        var folder = Path.Combine(_dir, "reports");
        Directory.CreateDirectory(folder);
        foreach (var (name, content) in files) { File.WriteAllBytes(Path.Combine(folder, name), content); }
        return folder;
    }

    private async Task<(int Code, string Output, string Error)> ImportAsync(string folder)
    {
        var (previousOut, previousError) = (Console.Out, Console.Error);
        using var output = new StringWriter();
        using var error = new StringWriter();

        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            var code = await ImportCommand.RunAsync(["--from", folder, "--db", _db], CancellationToken.None);
            return (code, output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(previousOut);
            Console.SetError(previousError);
        }
    }

    [Fact]
    public async Task ABadFileAmongGoodOnesIsNamedAndTheRestAreImported()
    {
        var folder = Folder(
            ("1-good.xml", Report("r-1")),
            ("2-damaged.zip", DamagedZip()),
            ("3-good.xml.gz", Gzip(Report("r-3"))),
            ("4-empty.xml", []));

        var (code, output, error) = await ImportAsync(folder);

        Assert.Equal(1, code);
        Assert.Contains("files seen      4", output, StringComparison.Ordinal);
        Assert.Contains("reports stored  2", output, StringComparison.Ordinal);
        Assert.Contains("not reports     1", output, StringComparison.Ordinal);
        Assert.Contains("failed          1 file(s)", output, StringComparison.Ordinal);
        Assert.Contains("2-damaged.zip: could not be opened as a zip archive", error, StringComparison.Ordinal);

        // Not the banner for an exception nobody expected, which is what the
        // damaged zip produced before.
        Assert.DoesNotContain("This is a bug", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFolderWithNothingWrongInItExitsZero()
    {
        var folder = Folder(("1-good.xml", Report("r-1")), ("2-good.xml.gz", Gzip(Report("r-2"))));

        var (code, output, error) = await ImportAsync(folder);

        Assert.Equal(0, code);
        Assert.Contains("reports stored  2", output, StringComparison.Ordinal);
        Assert.DoesNotContain("failed", output, StringComparison.Ordinal);
        Assert.Equal("", error);
    }

    [Fact]
    public async Task FailuresPastTheListedOnesAreCountedNotDropped()
    {
        // The list is capped so a bad folder cannot fill a screen. A list that
        // simply ended read as complete; the rest are counted.
        var files = Enumerable.Range(0, 30)
            .Select(i => ($"{i:D2}-damaged.zip", DamagedZip()))
            .ToArray();

        var (code, output, error) = await ImportAsync(Folder(files));

        Assert.Equal(1, code);
        Assert.Contains("failed          30 file(s)", output, StringComparison.Ordinal);
        Assert.Contains("and 5 more not listed", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFolderThatCannotBeOpenedIsNamedAndTheRestImported()
    {
        // A real folder with its mode taken away, which only shows anything
        // where the tests are not run as root - root opens it regardless.
        // The CI runner is not root. The importer's own tests cover the same
        // ground everywhere, with a listing made to refuse.
        if (OperatingSystem.IsWindows()) { return; }      // no mode to take away
        if (Environment.IsPrivilegedProcess) { return; }

        var folder = Folder(("1-good.xml", Report("r-1")), ("3-good.xml.gz", Gzip(Report("r-3"))));
        var locked = Path.Combine(folder, "2-locked");
        Directory.CreateDirectory(locked);
        File.WriteAllBytes(Path.Combine(locked, "r.xml"), Report("r-2"));
        File.SetUnixFileMode(locked, UnixFileMode.None);

        try
        {
            var (code, output, error) = await ImportAsync(folder);

            Assert.Equal(1, code);
            Assert.Contains("reports stored  2", output, StringComparison.Ordinal);
            Assert.Contains("failed          1 file(s)", output, StringComparison.Ordinal);
            Assert.Contains($"2-locked{Path.DirectorySeparatorChar}: could not be listed: ", error, StringComparison.Ordinal);

            // Not the banner for an exception nobody expected, which is what
            // the locked folder produced before.
            Assert.DoesNotContain("This is a bug", error, StringComparison.Ordinal);
        }
        finally
        {
            // Given back, or the folder could not be cleared away afterwards.
            File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }
}
