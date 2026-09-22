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

    // ---- upgrading one that is already here ----------------------------------
    //
    // A new release is extracted to a new folder, so somebody carrying their
    // database across brings one built by an older schema. Until this, the
    // only thing that would bring it up to date was `dmarc init-db`, named
    // nowhere a person upgrading would look - so the dashboard reported a
    // database it could not read, which reads as "it lost my data".

    /// <summary>
    /// The trial: it upgrades itself, and what was in it is still in it.
    /// </summary>
    [Fact]
    public async Task BringsATrialDatabaseUpToDateAndKeepsWhatWasInIt()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        await AnOlderDatabaseAsync(dbPath);
        await AddATenantAsync(dbPath, "Carried across");

        var logger = new CapturingLogger();
        await FirstRun.EnsureDatabaseAsync(dbPath, logger, mayUpgrade: true);

        Assert.Equal(DatabaseMigrations.BaselineVersion, await DatabaseMigrations.VersionAsync(dbPath));
        Assert.Empty(await DatabaseMigrations.PendingAsync(dbPath));

        // The half that matters. An upgrade that emptied the database would
        // pass every schema assertion above it.
        Assert.Equal("Carried across", await TheTenantAsync(dbPath));

        Assert.Contains(logger.Messages, m => m.Contains("brought up to date", StringComparison.Ordinal));
    }

    /// <summary>
    /// A server: left exactly as it was, and told what would change that.
    /// </summary>
    /// <remarks>
    /// Migrating a production database because a service restarted is a
    /// decision an operator makes - <c>deploy/update.sh</c> runs
    /// <c>dmarc init-db</c> and means it. What was missing is that refusing
    /// used to be silent, so the operator got "no such column: mta_sts_mode"
    /// on one page at a time and nothing naming the upgrade.
    /// </remarks>
    [Fact]
    public async Task LeavesAServerDatabaseAloneAndSaysWhatWouldUpgradeIt()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        var was = await AnOlderDatabaseAsync(dbPath);

        var logger = new CapturingLogger();
        await FirstRun.EnsureDatabaseAsync(dbPath, logger);

        Assert.Equal(was, await DatabaseMigrations.VersionAsync(dbPath));
        Assert.NotEmpty(await DatabaseMigrations.PendingAsync(dbPath));
        Assert.Contains(logger.Messages, m => m.Contains("dmarc init-db", StringComparison.Ordinal));
    }

    /// <summary>
    /// The trial again, with nothing to do. Asserted on the bytes, because an
    /// upgrade path that rewrites a database it had no business touching is
    /// the failure this whole file exists to prevent.
    /// </summary>
    [Fact]
    public async Task AnUpToDateDatabaseIsNotWrittenToEvenWhereUpgradingIsAllowed()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        await new ReportStore(dbPath).InitializeAsync(DatabaseSchema.Sql);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        var before = await File.ReadAllBytesAsync(dbPath);
        var logger = new CapturingLogger();

        await FirstRun.EnsureDatabaseAsync(dbPath, logger, mayUpgrade: true);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        Assert.Equal(before, await File.ReadAllBytesAsync(dbPath));
        Assert.DoesNotContain(logger.Messages, m => m.Contains("brought up to date", StringComparison.Ordinal));
    }

    /// <summary>
    /// The other direction: two folders, and the older copy opened second.
    /// Nothing here can undo a migration, so it says so rather than leaving a
    /// page to fail on a column this build has never heard of.
    /// </summary>
    [Fact]
    public async Task ADatabaseFromANewerBuildIsNamedRatherThanTouched()
    {
        using var dir = new TempDir();
        var dbPath = Path.Combine(dir.Path, "dmarc.db");
        await new ReportStore(dbPath).InitializeAsync(DatabaseSchema.Sql);

        await using (var db = Open(dbPath))
        {
            await using var ahead = db.CreateCommand();
            ahead.CommandText =
                "INSERT INTO schema_migrations (version, applied_at, description) "
                + "VALUES ('9999', '2030-01-01 00:00:00', 'from a later build')";
            await ahead.ExecuteNonQueryAsync();
        }

        var logger = new CapturingLogger();
        await FirstRun.EnsureDatabaseAsync(dbPath, logger, mayUpgrade: true);

        Assert.Contains(logger.Messages, m => m.Contains("newer than", StringComparison.Ordinal));
    }

    // ---- helpers -------------------------------------------------------------

    private static Microsoft.Data.Sqlite.SqliteConnection Open(string dbPath)
    {
        var db = new Microsoft.Data.Sqlite.SqliteConnection(
            new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        db.Open();
        return db;
    }

    /// <summary>
    /// A database as the previous release left it: the current schema, with
    /// the last migration undone so it is genuinely one that never had it.
    /// </summary>
    /// <remarks>
    /// The thorough version of this - every migration, in order, with the
    /// reasons each undo is shaped the way it is - lives in
    /// <c>DatabaseMigrationTests</c> in Core. This needs only "one release
    /// behind", which is the case a person upgrading actually has.
    /// </remarks>
    private static async Task<string> AnOlderDatabaseAsync(string dbPath)
    {
        await new ReportStore(dbPath).InitializeAsync(DatabaseSchema.Sql);

        var last = DatabaseMigrations.All[^1];
        await using var db = Open(dbPath);

        // Indexes first: SQLite refuses to drop a column an index still
        // mentions, and names the index rather than the migration when it does.
        foreach (var index in Matches(last.Sql, @"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)"))
        {
            await ExecuteAsync(db, $"DROP INDEX IF EXISTS {index[0]}");
        }

        foreach (var added in Matches(last.Sql, @"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)"))
        {
            await ExecuteAsync(db, $"ALTER TABLE {added[0]} DROP COLUMN {added[1]}");
        }

        foreach (var table in Matches(last.Sql, @"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)"))
        {
            await ExecuteAsync(db, $"DROP TABLE IF EXISTS {table[0]}");
        }

        await ExecuteAsync(db, $"DELETE FROM schema_migrations WHERE version = '{last.Version}'");

        return DatabaseMigrations.All[^2].Version;
    }

    private static List<string[]> Matches(string sql, string pattern) =>
    [
        .. System.Text.RegularExpressions.Regex
            .Matches(sql, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            .Select(m => m.Groups.Values.Skip(1).Select(g => g.Value).ToArray())
    ];

    private static async Task ExecuteAsync(Microsoft.Data.Sqlite.SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task AddATenantAsync(string dbPath, string name)
    {
        await using var db = Open(dbPath);
        await using var insert = db.CreateCommand();
        insert.CommandText =
            "INSERT INTO tenants (id, name, slug, created_at, updated_at) "
            + "VALUES ('t1', $name, 'carried', '2026-09-22', '2026-09-22')";
        insert.Parameters.AddWithValue("$name", name);
        await insert.ExecuteNonQueryAsync();
    }

    private static async Task<string?> TheTenantAsync(string dbPath)
    {
        await using var db = Open(dbPath);
        await using var read = db.CreateCommand();
        read.CommandText = "SELECT name FROM tenants WHERE id = 't1'";
        return await read.ExecuteScalarAsync() as string;
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
