using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Bringing an existing database up to the current schema.
///
/// This exists because it was missing and the gap bit: a table was added to
/// schema.sql, which builds new databases and does nothing to old ones, and
/// the first code to touch that table failed with "no such table" against
/// every database created before it. On a server that is not a bad deploy, it
/// is an outage.
///
/// So the property these hold to is: whatever version a database is at, the
/// current build works against it after this has run, and running it twice
/// changes nothing.
/// </summary>
public sealed class DatabaseMigrationTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-migrate-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString());
        db.Open();
        return db;
    }

    /// <summary>A database as an older build left it: current schema, minus what came after.</summary>
    private async Task<string> AnOlderDatabaseAsync(string upToVersion)
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        await using var db = Open();

        // Undo everything at or after the version, so this is genuinely a
        // database that never had it rather than one that has it hidden.
        // Newest first, so a column added by one migration is gone before the
        // table it was added to is dropped by an earlier one's undo.
        foreach (var migration in DatabaseMigrations.All
                     .Where(m => string.CompareOrdinal(m.Version, upToVersion) >= 0)
                     .OrderByDescending(m => m.Version, StringComparer.Ordinal))
        {
            // Indexes first. SQLite refuses to drop a column an index still
            // mentions, and the message - "error in index <name> after drop
            // column" - names the index rather than the migration, so this is
            // worth getting right here instead of in whoever adds one next.
            foreach (var index in IndexesIn(migration.Sql))
            {
                await using var drop = db.CreateCommand();
                drop.CommandText = $"DROP INDEX IF EXISTS {index}";
                await drop.ExecuteNonQueryAsync();
            }

            foreach (var (table, column) in ColumnsAddedIn(migration.Sql))
            {
                await using var drop = db.CreateCommand();
                drop.CommandText = $"ALTER TABLE {table} DROP COLUMN {column}";
                await drop.ExecuteNonQueryAsync();
            }

            foreach (var table in TablesIn(migration.Sql))
            {
                await using var drop = db.CreateCommand();
                drop.CommandText = $"DROP TABLE IF EXISTS {table}";
                await drop.ExecuteNonQueryAsync();
            }

            await using var forget = db.CreateCommand();
            forget.CommandText = "DELETE FROM schema_migrations WHERE version = $v";
            forget.Parameters.AddWithValue("$v", migration.Version);
            await forget.ExecuteNonQueryAsync();
        }

        return upToVersion;
    }

    private static IEnumerable<string> TablesIn(string sql) =>
        sql.Split('\n')
           .Where(line => line.TrimStart().StartsWith("CREATE TABLE ", StringComparison.OrdinalIgnoreCase))
           .Select(line => line.Trim()["CREATE TABLE ".Length..].Split(' ', '(')[0]);

    /// <summary>The indexes a migration creates, unique or not.</summary>
    private static IEnumerable<string> IndexesIn(string sql) =>
        System.Text.RegularExpressions.Regex
            .Matches(sql, @"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            .Select(m => m.Groups[1].Value);

    /// <summary>The columns a migration adds to tables that already existed.</summary>
    private static IEnumerable<(string Table, string Column)> ColumnsAddedIn(string sql) =>
        System.Text.RegularExpressions.Regex
            .Matches(sql, @"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value));

    private async Task<bool> HasTableAsync(string name)
    {
        await using var db = Open();
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$n";
        command.Parameters.AddWithValue("$n", name);
        return Convert.ToInt64(await command.ExecuteScalarAsync()) > 0;
    }

    // ---- the whole point -----------------------------------------------------

    [Fact]
    public async Task BringsADatabaseFromAnOlderBuildUpToDate()
    {
        await AnOlderDatabaseAsync("0009");
        Assert.False(await HasTableAsync("mta_sts_policies"));

        var result = await DatabaseMigrations.ApplyAsync(_dbPath);

        Assert.True(result.Changed);
        Assert.True(await HasTableAsync("mta_sts_policies"));
        Assert.Equal(DatabaseMigrations.BaselineVersion, result.Version);
    }

    [Fact]
    public async Task ADatabaseTheSchemaJustBuiltNeedsNothing()
    {
        // schema.sql is complete and records every version, so a fresh
        // install must not have migrations replayed into it - they would fail
        // on tables that are already there.
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        var result = await DatabaseMigrations.ApplyAsync(_dbPath);

        Assert.False(result.Changed);
        Assert.Empty(result.Applied);
    }

    [Fact]
    public async Task RunningItTwiceChangesNothingTheSecondTime()
    {
        await AnOlderDatabaseAsync("0009");

        var first = await DatabaseMigrations.ApplyAsync(_dbPath);
        var second = await DatabaseMigrations.ApplyAsync(_dbPath);

        Assert.True(first.Changed);
        Assert.False(second.Changed);
    }

    [Fact]
    public async Task SaysWhatIsPendingWithoutApplyingIt()
    {
        await AnOlderDatabaseAsync("0009");

        var pending = await DatabaseMigrations.PendingAsync(_dbPath);

        Assert.NotEmpty(pending);
        Assert.False(await HasTableAsync("mta_sts_policies"));
    }

    [Fact]
    public async Task DataAlreadyInTheDatabaseSurvives()
    {
        // The reason this is a migration rather than "delete it and re-run
        // the schema": there are years of somebody's reports in here.
        await AnOlderDatabaseAsync("0009");

        await using (var db = Open())
        {
            await using var insert = db.CreateCommand();
            insert.CommandText =
                "INSERT INTO tenants (id, name, slug, deployment_mode, status, secret_backend, created_at, updated_at) "
                + "VALUES ('t1', 'Local', 'local', 'self_hosted', 'active', 'dpapi', '2026-01-01', '2026-01-01')";
            await insert.ExecuteNonQueryAsync();
        }

        await DatabaseMigrations.ApplyAsync(_dbPath);

        await using var check = Open();
        await using var count = check.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM tenants WHERE id = 't1'";
        Assert.Equal(1L, Convert.ToInt64(await count.ExecuteScalarAsync()));
    }

    [Fact]
    public void EveryMigrationIsNumberedAndInOrder()
    {
        // The order they run in is the order of their versions, so two with
        // the same number, or one that sorts wrongly, would apply in an order
        // nobody chose.
        var versions = DatabaseMigrations.All.Select(m => m.Version).ToList();

        Assert.Equal(versions, versions.OrderBy(v => v, StringComparer.Ordinal));
        Assert.Equal(versions.Count, versions.Distinct(StringComparer.Ordinal).Count());
        Assert.All(versions, v => Assert.Matches("^[0-9]{4}$", v));
    }

    [Fact]
    public void TheBaselineCoversEveryMigrationThatExists()
    {
        // schema.sql claims to be at BaselineVersion. A migration numbered
        // above it would never run against a fresh database, so the table it
        // adds would exist only on upgraded ones.
        Assert.All(
            DatabaseMigrations.All,
            m => Assert.True(
                string.CompareOrdinal(m.Version, DatabaseMigrations.BaselineVersion) <= 0,
                $"migration {m.Version} is newer than the baseline {DatabaseMigrations.BaselineVersion}, "
                + "so schema.sql does not contain it"));
    }

    [Fact]
    public async Task TheSchemaAndTheMigrationsAgreeAboutTheVersion()
    {
        // A fresh database must report the baseline. If schema.sql stopped
        // recording a version, an upgrade would replay migrations into a
        // database that already had them.
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);

        Assert.Equal(DatabaseMigrations.BaselineVersion, await DatabaseMigrations.VersionAsync(_dbPath));
    }
}

/// <summary>
/// Asking whether a database exists must not create one.
/// </summary>
/// <remarks>
/// Opening a SQLite path that is not there creates it, and every command asks
/// this question before doing anything. So running one in the wrong directory
/// used to leave an empty dmarc.db behind, print "run dmarc init-db", and then
/// init-db would refuse because the file it had just created itself did not
/// look like a DMARC Monitor database - a dead end reached by following the
/// instructions exactly.
/// </remarks>
public sealed class DatabaseExistenceTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-exists-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task AskingAboutADatabaseThatIsNotThereLeavesNothingBehind()
    {
        Assert.False(await new ReportStore(_dbPath).IsInitializedAsync());

        Assert.False(File.Exists(_dbPath));
    }

    [Fact]
    public async Task AndTheAnswerIsStillRightOnceItExists()
    {
        var store = new ReportStore(_dbPath);
        await store.InitializeAsync(DatabaseSchema.Sql);

        Assert.True(await store.IsInitializedAsync());
    }
}
