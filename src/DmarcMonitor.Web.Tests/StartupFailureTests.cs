using Microsoft.AspNetCore.Connections;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// What is left behind when the application cannot start.
///
/// The bug these came from was reported as "the app appears like it opens
/// then just closes with a shadow". On a server a startup failure goes to the
/// journal and somebody reads it; in a console window Explorer created and
/// owns, it goes nowhere at all, because the window is destroyed on the same
/// tick the process exits. Every assertion below is about leaving evidence
/// that outlives the window.
/// </summary>
public sealed class StartupFailureTests
{
    [Fact]
    public void SaysTheSoftwareCouldNotStart()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        var code = StartupFailure.Report(new InvalidOperationException("nope"), dir.Path);

        // 70 is EX_SOFTWARE. It matters because it is what a launcher script
        // or a service manager tests to decide whether to say anything.
        Assert.Equal(70, code);
    }

    [Fact]
    public void WritesTheDetailToAFileBesideTheDatabase()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        StartupFailure.Report(new InvalidOperationException("the specific thing that broke"), dir.Path);

        var log = Path.Combine(dir.Path, "startup-error.log");
        Assert.True(File.Exists(log));

        var written = File.ReadAllText(log);
        Assert.Contains("the specific thing that broke", written, StringComparison.Ordinal);

        // A log that does not say which build it came from cannot be matched
        // against a release, which is the first question asked about one.
        Assert.Contains(DmarcMonitor.Core.Updates.BuildInfo.Version, written, StringComparison.Ordinal);

        // And the window says where it went, or the file may as well not exist.
        Assert.Contains(log, console.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The failure a person actually hits on their own machine: something is
    /// already on port 5000. Kestrel reports it as an IOException whose
    /// message is about binding, with the real cause underneath - so the
    /// explanation has to come from walking the chain, not from the top.
    /// </summary>
    [Fact]
    public void ExplainsAPortClashInWordsAndSaysWhatToDo()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        var kestrel = new IOException(
            "Failed to bind to address http://127.0.0.1:5000: address already in use.",
            new AddressInUseException("Address already in use"));

        StartupFailure.Report(kestrel, dir.Path);

        Assert.Contains("already using the port", console.Text, StringComparison.Ordinal);
        Assert.Contains("ASPNETCORE_URLS", console.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void ExplainsAReadOnlyFolderByNamingTheTwoThatCatchPeople()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        StartupFailure.Report(new UnauthorizedAccessException("Access to the path is denied."), dir.Path);

        Assert.Contains("cannot be written to", console.Text, StringComparison.Ordinal);
        Assert.Contains("Program Files", console.Text, StringComparison.Ordinal);
        Assert.Contains(".zip", console.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void QuotesSqliteRatherThanParaphrasingIt()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        StartupFailure.Report(new SqliteException("file is not a database", 26), dir.Path);

        Assert.Contains("file is not a database", console.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The honest case. Inventing friendly advice for a failure nobody has
    /// had produces confident wrong instructions, so an unrecognized one is
    /// named as itself and flagged as worth reporting.
    /// </summary>
    [Fact]
    public void AdmitsWhenItCannotExplainSomething()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        StartupFailure.Report(new BadImageFormatException("wrong architecture"), dir.Path);

        Assert.Contains("BadImageFormatException", console.Text, StringComparison.Ordinal);
        Assert.Contains("wrong architecture", console.Text, StringComparison.Ordinal);
        Assert.Contains("worth reporting", console.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// If the folder cannot be written to, the reason for that is very often
    /// the failure being reported - so failing to write the log must not lose
    /// the report. It falls back, and if even that fails it prints what the
    /// file would have held.
    /// </summary>
    [Fact]
    public void StillReportsWhenTheLogCannotBeWritten()
    {
        using var dir = new TempDir();

        // A file standing where the directory should be. CreateDirectory
        // throws on this whatever the process's privileges are, which a
        // permission bit would not do for root in CI.
        var notADirectory = Path.Combine(dir.Path, "wall");
        File.WriteAllText(notADirectory, "");

        using var console = new CapturedError();
        var code = StartupFailure.Report(new InvalidOperationException("still broke"), notADirectory);

        Assert.Equal(70, code);
        Assert.Contains("still broke", console.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The one that would hang CI, a service or a pipeline if it were wrong.
    /// Reporting must never block waiting for a keystroke that is not coming;
    /// the pause only happens in a window this process owns, and a test
    /// process never owns one.
    /// </summary>
    [Fact]
    public async Task ReturnsRatherThanWaitingForAKeyThatIsNotComing()
    {
        using var dir = new TempDir();
        using var console = new CapturedError();

        var done = Task.Run(() => StartupFailure.Report(new InvalidOperationException("x"), dir.Path));

        var first = await Task.WhenAny(done, Task.Delay(TimeSpan.FromSeconds(10)));

        Assert.True(ReferenceEquals(first, done), "Report blocked; it would hang a service or CI");
    }

    private sealed class CapturedError : IDisposable
    {
        private readonly TextWriter _previous = Console.Error;
        private readonly StringWriter _captured = new();

        public CapturedError() => Console.SetError(_captured);

        public string Text => _captured.ToString();

        public void Dispose()
        {
            Console.SetError(_previous);
            _captured.Dispose();
        }
    }

    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"dmarc-startup-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
