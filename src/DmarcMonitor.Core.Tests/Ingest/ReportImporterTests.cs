using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// The importer behind both the Import page and <c>dmarc import</c>.
///
/// It had no tests of its own: the extraction beneath it is tested to death
/// and the page above it is exercised, and the importer between them was
/// assumed to be too thin to get wrong. It was not wrong, but the command in
/// front of it was: an export is one zip file, and pointing the command at
/// one was refused as "No such folder" for a file that was plainly there.
/// </summary>
public sealed class ReportImporterTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-importer-{Guid.NewGuid():N}");
    private readonly string _dbPath;

    public ReportImporterTests()
    {
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "dmarc.db");
        new ReportStore(_dbPath).InitialiseAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private ReportImporter Importer() => new(new ReportStore(_dbPath));

    [Theory]
    [InlineData("google-aggregate.zip")]
    [InlineData("google-aggregate.xml")]
    [InlineData("google-tlsrpt.json.gz")]
    public async Task ASingleFileImportsWhateverItHolds(string fixture)
    {
        // A zip, a bare report, a gzipped one: the same three shapes the
        // browser accepts, from a path instead of a drop.
        var result = await Importer().ImportFileAsync(Fixture(fixture));

        Assert.Equal(1, result.FilesSeen);
        Assert.Equal(1, result.Stored);
        Assert.Equal(0, result.Failed);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task ImportingTheSameFileTwiceStoresItOnce()
    {
        // Re-running an import must resume, not double. This is what makes an
        // interrupted import safe to run again.
        await Importer().ImportFileAsync(Fixture("google-aggregate.zip"));
        var again = await Importer().ImportFileAsync(Fixture("google-aggregate.zip"));

        Assert.Equal(0, again.Stored);
        Assert.Equal(1, again.AlreadyStored);
    }

    [Fact]
    public async Task AFolderImportsEveryFileInItIncludingSubfolders()
    {
        var folder = Path.Combine(_dir, "export");
        Directory.CreateDirectory(Path.Combine(folder, "nested"));
        File.Copy(Fixture("google-aggregate.zip"), Path.Combine(folder, "a.zip"));
        File.Copy(Fixture("outlook-aggregate.xml.gz"), Path.Combine(folder, "nested", "b.xml.gz"));
        File.WriteAllText(Path.Combine(folder, "notes.txt"), "not a report");

        var result = await Importer().ImportFolderAsync(folder);

        Assert.Equal(3, result.FilesSeen);
        Assert.Equal(2, result.Stored);
        Assert.Equal(1, result.NotReports);
        Assert.Equal(0, result.Failed);
    }

    [Fact]
    public async Task AFileThatIsNotAReportIsCountedNotFailed()
    {
        // Somebody pointing this at the wrong file gets a count that says so,
        // not an error that reads as the importer being broken.
        var path = Path.Combine(_dir, "readme.txt");
        File.WriteAllText(path, "hello");

        var result = await Importer().ImportFileAsync(path);

        Assert.Equal(1, result.NotReports);
        Assert.Equal(0, result.Stored);
        Assert.Equal(0, result.Failed);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
