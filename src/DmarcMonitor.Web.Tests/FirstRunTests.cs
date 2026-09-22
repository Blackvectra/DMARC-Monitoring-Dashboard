using DmarcMonitor.Core.Storage;
using Microsoft.Extensions.Logging;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// What the application does when it is started without a database.
///
/// This went unnoticed for as long as it did because every path that runs the
/// web app runs <c>dmarc init-db</c> first: <c>deploy/install.sh</c> does,
/// <c>bootstrap.sh</c> does, and the tests build their own. So the one case
/// nothing covered was the one a person downloading a copy would hit, and
/// there it left a zero-byte <c>dmarc.db</c> and put "Could not read the
/// database: no such table: tenants" on every screen.
///
/// The risk in fixing it is the opposite mistake - an application that helps
/// itself to a file it should not have touched - so most of what is below is
/// about what it must NOT do.
/// </summary>
public sealed class FirstRunTests
{
    [Fact]
    public async Task CreatesTheDatabaseWhenThereIsNone()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");

        await FirstRun.EnsureDatabaseAsync(dbPath, new CapturingLogger());

        Assert.True(File.Exists(dbPath));
        Assert.True(await new ReportStore(dbPath).IsInitializedAsync());
    }

    /// <summary>
    /// A path that was opened and never written to leaves a zero-byte file.
    /// That is what the old behaviour produced, so an install that had already
    /// been started once had to be able to recover by itself - otherwise the
    /// fix would only work for somebody who had never run the broken version.
    /// </summary>
    [Fact]
    public async Task CreatesTheDatabaseOverAZeroByteFile()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        await File.WriteAllBytesAsync(dbPath, []);

        await FirstRun.EnsureDatabaseAsync(dbPath, new CapturingLogger());

        Assert.True(await new ReportStore(dbPath).IsInitializedAsync());
    }

    [Fact]
    public async Task CreatesTheDirectoryWhenItIsMissingToo()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "not", "made", "yet", "dmarc.db");

        await FirstRun.EnsureDatabaseAsync(dbPath, new CapturingLogger());

        Assert.True(await new ReportStore(dbPath).IsInitializedAsync());
    }

    /// <summary>
    /// The one that matters on a server. A restart must be a restart, not a
    /// migration and certainly not a fresh database over somebody's history.
    /// </summary>
    [Fact]
    public async Task LeavesAnExistingDatabaseExactlyAsItWas()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        await new ReportStore(dbPath).InitializeAsync(DatabaseSchema.Sql);

        var before = await File.ReadAllBytesAsync(dbPath);
        var logger = new CapturingLogger();

        await FirstRun.EnsureDatabaseAsync(dbPath, logger);

        Assert.Equal(before, await File.ReadAllBytesAsync(dbPath));
        Assert.DoesNotContain(logger.Messages, m => m.Contains("Created a new database", StringComparison.Ordinal));
    }

    /// <summary>
    /// Somebody else's file, at the configured path. Overwriting it would be
    /// destroying data to fix a convenience, so it is left alone and the
    /// reason is logged - the pages then report a database they cannot read,
    /// which is now true rather than mysterious.
    /// </summary>
    [Fact]
    public async Task WillNotTouchAFileThatIsNotADatabase()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        const string theirs = "this is not a database, it is somebody's notes";
        await File.WriteAllTextAsync(dbPath, theirs);

        var logger = new CapturingLogger();
        await FirstRun.EnsureDatabaseAsync(dbPath, logger);

        Assert.Equal(theirs, await File.ReadAllTextAsync(dbPath));
        Assert.Contains(logger.Messages, m => m.Contains("not a DMARC Monitor database", StringComparison.Ordinal));
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            Messages.Add(formatter(state, exception));
        }
    }

    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"dmarc-firstrun-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            // SQLite may still hold the file on Windows for a moment after the
            // connection is pooled; a failed cleanup is not a failed test.
            try { Directory.Delete(Path, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
