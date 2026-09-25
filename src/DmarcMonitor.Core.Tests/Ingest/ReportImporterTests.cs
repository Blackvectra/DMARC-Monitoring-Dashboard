using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;
using static DmarcMonitor.Core.Tests.Ingest.SyntheticReports;

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
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private ReportImporter Importer(Func<string, (string[] Files, string[] Folders)>? listFolder = null) =>
        new(new ReportStore(_dbPath), listFolder);

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

    // ---- one bad file among good ones ------------------------------------------

    private string Folder(params (string Name, byte[] Content)[] files) =>
        Subfolder(_dir, $"in-{Guid.NewGuid():N}", files);

    private static string Subfolder(string parent, string name, params (string Name, byte[] Content)[] files)
    {
        var folder = Path.Combine(parent, name);
        Directory.CreateDirectory(folder);
        foreach (var (file, content) in files) { File.WriteAllBytes(Path.Combine(folder, file), content); }
        return folder;
    }

    /// <summary>
    /// The one this is about. A zip whose list of contents was damaged threw
    /// from inside the extraction, which nothing caught: the import ended at
    /// that file, everything after it in the folder was never read, and the
    /// command called it a bug. Each kind of bad file sits between good ones
    /// here, and every good one has to come through.
    /// </summary>
    [Fact]
    public async Task OneBadFileDoesNotStopTheRestOfTheFolder()
    {
        var folder = Folder(
            ("01-good.xml", Bytes(AggregateXml("r-1"))),
            ("02-damaged.zip", WithDamagedListOfContents(Zip(("r.xml", Bytes(AggregateXml("r-damaged")))))),
            ("03-good.xml.gz", Gzip(AggregateXml("r-3"))),
            ("04-truncated.xml.gz", CutShort(Gzip(AggregateXml("r-truncated")))),
            ("05-good.zip", Zip(("inner.xml.gz", Gzip(AggregateXml("r-5"))))),
            ("06-not-a-report.zip", Zip(("readme.txt", Bytes("nothing to see here")))),
            ("07-empty.xml", []),
            ("08-cut-short.zip", CutShort(Zip(("r.xml", Bytes(AggregateXml("r-cut")))))),
            ("09-good.json.gz", Gzip(TlsJson("t-9"))));

        var result = await Importer().ImportFolderAsync(folder);

        Assert.False(result.StoppedEarly);
        Assert.Equal(9, result.FilesSeen);
        Assert.Equal(4, result.Stored);
        Assert.Equal(2, result.NotReports);
        Assert.Equal(3, result.Failed);
        Assert.Equal(3, result.FailedFiles);

        // Named, each of them, by the file on disk.
        Assert.Collection(result.Errors,
            e => Assert.StartsWith("02-damaged.zip: could not be opened as a zip archive", e, StringComparison.Ordinal),
            e => Assert.StartsWith("04-truncated.xml.gz: cut short", e, StringComparison.Ordinal),
            e => Assert.StartsWith("08-cut-short.zip: could not be opened as a zip archive", e, StringComparison.Ordinal));

        // And the good ones really are in the database: importing again finds
        // every one of them already there.
        var again = await Importer().ImportFolderAsync(folder);
        Assert.Equal(0, again.Stored);
        Assert.Equal(4, again.AlreadyStored);
    }

    [Fact]
    public async Task ADamagedReportInsideAnExportIsNamedAndTheRestOfTheExportImported()
    {
        var path = Path.Combine(_dir, "export.zip");
        File.WriteAllBytes(path, Zip(
            ("a.xml.gz", Gzip(AggregateXml("r-a"))),
            ("bad.xml.gz", CutShort(Gzip(AggregateXml("r-bad")))),
            ("c.xml.gz", Gzip(AggregateXml("r-c")))));

        var result = await Importer().ImportFileAsync(path);

        Assert.Equal(2, result.Stored);
        Assert.Equal(1, result.Failed);
        Assert.Equal(1, result.FailedFiles);
        Assert.Equal(0, result.NotReports);
        Assert.StartsWith("export.zip: bad.xml.gz: cut short", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATlsReportNamingNoDomainIsAFailureNotOneAlreadyStored()
    {
        // The store declines a TLS report with no policy domain to file it
        // under, with the same null it returns for a duplicate - and it was
        // counted as one: "already stored", for a report that never was.
        var path = Path.Combine(_dir, "tls.json");
        File.WriteAllText(path, TlsJson("t-empty", policies: "[]"));

        var result = await Importer().ImportFileAsync(path);

        Assert.Equal(0, result.Stored);
        Assert.Equal(0, result.AlreadyStored);
        Assert.Equal(1, result.Failed);
        Assert.Contains("names no policy domain", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReportThatWillNotParseIsNamedByTheFileItArrivedIn()
    {
        // Named by its own name alone, a report inside one of forty exports is
        // a needle; and a gzipped one lost its .gz, naming a file nobody has.
        var export = Path.Combine(_dir, "export.zip");
        File.WriteAllBytes(export, Zip(("broken.xml", Bytes("<feedback><unclosed>"))));
        var gz = Path.Combine(_dir, "broken.xml.gz");
        File.WriteAllBytes(gz, Gzip("<feedback><unclosed>"));

        var fromExport = await Importer().ImportFileAsync(export);
        var fromGz = await Importer().ImportFileAsync(gz);

        Assert.StartsWith("export.zip: broken.xml: ", Assert.Single(fromExport.Errors), StringComparison.Ordinal);
        Assert.StartsWith("broken.xml.gz: ", Assert.Single(fromGz.Errors), StringComparison.Ordinal);
        Assert.DoesNotContain("broken.xml.gz: broken.xml", fromGz.Errors[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task FailuresInOneFileAreCountedAsOneFile()
    {
        // "3 failed" does not say whether that was one file or three, which is
        // the first thing somebody fixing it needs to know.
        var path = Path.Combine(_dir, "export.zip");
        File.WriteAllBytes(path, Zip(
            ("a.xml", Bytes("<feedback><unclosed>")),
            ("b.xml", Bytes("<feedback><unclosed>")),
            ("c.xml", Bytes("<feedback><unclosed>"))));

        var result = await Importer().ImportFileAsync(path);

        Assert.Equal(3, result.Failed);
        Assert.Equal(1, result.FailedFiles);
        Assert.Equal(0, result.NotReports);
    }

    // ---- a folder that cannot be listed, or is a link --------------------------

    /// <summary>Access denied, in the framework's own words.</summary>
    /// <remarks>
    /// Thrown by a stand-in for the listing rather than got from a folder's
    /// mode, because root opens any folder whatever its mode, and root is who
    /// these tests run as in a container. The command's tests take a real
    /// mode away where they are not root.
    /// </remarks>
    private static UnauthorizedAccessException Denied(string path) => new($"Access to the path '{path}' is denied.");

    /// <summary>
    /// The one this is about. A subfolder that could not be opened threw out
    /// of the framework's recursive listing before a single file was read:
    /// the whole import ended and the command called it a bug. It is named
    /// now, in its place among the files, and everything else comes through.
    /// </summary>
    [Fact]
    public async Task AFolderThatCannotBeListedIsNamedAndTheRestImported()
    {
        var folder = Folder(
            ("1-good.xml", Bytes(AggregateXml("r-1"))),
            ("2-damaged.zip", WithDamagedListOfContents(Zip(("r.xml", Bytes(AggregateXml("r-2")))))),
            ("6-damaged.zip", WithDamagedListOfContents(Zip(("r.xml", Bytes(AggregateXml("r-6")))))));
        var locked = Subfolder(folder, "3-locked", ("r.xml", Bytes(AggregateXml("r-3"))));
        var open = Subfolder(folder, "4-open", ("r.xml", Bytes(AggregateXml("r-4"))));
        var lockedToo = Subfolder(open, "5-locked-too", ("r.xml", Bytes(AggregateXml("r-5"))));

        var importer = Importer(dir => dir == locked || dir == lockedToo ? throw Denied(dir) : ReportImporter.ListOnDisk(dir));
        var result = await importer.ImportFolderAsync(folder);

        Assert.False(result.StoppedEarly);
        Assert.Equal(6, result.FilesSeen);
        Assert.Equal(2, result.Stored);
        Assert.Equal(4, result.Failed);
        Assert.Equal(4, result.FailedFiles);

        // Each named by its path within the import, and where its files would
        // have been, so the list reads in the same order as the folder.
        var s = Path.DirectorySeparatorChar;
        Assert.Collection(result.Errors,
            e => Assert.StartsWith("2-damaged.zip: could not be opened as a zip archive", e, StringComparison.Ordinal),
            e => Assert.Equal($"3-locked{s}: could not be listed: Access to the path '{locked}' is denied.", e),
            e => Assert.Equal($"4-open{s}5-locked-too{s}: could not be listed: Access to the path '{lockedToo}' is denied.", e),
            e => Assert.StartsWith("6-damaged.zip: could not be opened as a zip archive", e, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFolderRemovedPartWayThroughIsNamedNotDropped()
    {
        // Somebody tidying up while an import runs: the folder was there when
        // the one around it was listed, and gone by its own turn. The
        // recursive listing passed over a folder like that without a word,
        // and over the reports that had been in it.
        var folder = Folder(("1-good.xml", Bytes(AggregateXml("r-1"))));
        var gone = Subfolder(folder, "2-gone", ("r.xml", Bytes(AggregateXml("r-2"))));
        Subfolder(folder, "3-kept", ("r.xml", Bytes(AggregateXml("r-3"))));

        var importer = Importer(dir =>
        {
            var listing = ReportImporter.ListOnDisk(dir);
            if (dir == folder) { Directory.Delete(gone, recursive: true); }
            return listing;
        });
        var result = await importer.ImportFolderAsync(folder);

        Assert.Equal(2, result.Stored);
        Assert.Equal(1, result.Failed);
        Assert.StartsWith($"2-gone{Path.DirectorySeparatorChar}: could not be listed: ",
            Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheFolderBeingImportedIsNamedByItsOwnNameWhenItCannotBeListed()
    {
        // It has no path within the import, being the import.
        var folder = Folder(("1-good.xml", Bytes(AggregateXml("r-1"))));

        var result = await Importer(dir => throw Denied(dir)).ImportFolderAsync(folder);

        Assert.Equal(0, result.Stored);
        Assert.Equal(1, result.Failed);
        Assert.Equal(
            $"{Path.GetFileName(folder)}{Path.DirectorySeparatorChar}: could not be listed: Access to the path '{folder}' is denied.",
            Assert.Single(result.Errors));
    }

    /// <summary>
    /// The recursive listing followed a link to a folder, and one pointing
    /// back up the tree had it list the same files again at every level,
    /// forty levels deep on Linux. Not followed now, and named rather than
    /// passed over, because a link to a folder elsewhere holds reports that
    /// used to come in through it.
    /// </summary>
    [Fact]
    public async Task ALinkToAFolderIsNamedAndNotFollowed()
    {
        if (OperatingSystem.IsWindows()) { return; }   // making a link needs Developer Mode or an administrator

        var folder = Folder(("1-good.xml", Bytes(AggregateXml("r-1"))));
        var elsewhere = Folder(("r.xml", Bytes(AggregateXml("r-elsewhere"))));
        Directory.CreateSymbolicLink(Path.Combine(folder, "2-elsewhere"), elsewhere);
        Directory.CreateSymbolicLink(Path.Combine(folder, "3-loop"), folder);

        // A link to a file is still read, as it always was. It cannot loop.
        File.CreateSymbolicLink(Path.Combine(folder, "4-linked.xml"), Path.Combine(elsewhere, "r.xml"));

        var result = await Importer().ImportFolderAsync(folder);

        // Nothing read twice: through the loop, the first file would have
        // been; through the other link, the report the file link points at.
        Assert.Equal(4, result.FilesSeen);
        Assert.Equal(2, result.Stored);
        Assert.Equal(0, result.AlreadyStored);
        Assert.Equal(2, result.Failed);

        var s = Path.DirectorySeparatorChar;
        Assert.Collection(result.Errors,
            e => Assert.Equal($"2-elsewhere{s}: a link to another folder, not followed", e),
            e => Assert.Equal($"3-loop{s}: a link to another folder, not followed", e));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
