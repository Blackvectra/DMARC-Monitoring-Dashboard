using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Taking a copy of the database.
///
/// The only thing here that protects the reports, on a product designed to run
/// on one machine. So the behaviour that matters is not "a file appeared" -
/// it is that the file is a real database with the data in it, that a bad copy
/// is never left looking like a good one, and that a failed run never costs
/// somebody the backup they already had.
/// </summary>
public sealed class BackupServiceTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-backup-src-{Guid.NewGuid():N}.db");

    private readonly string _dir =
        Path.Combine(Path.GetTempPath(), $"dmarc-backup-out-{Guid.NewGuid():N}");

    public BackupServiceTests()
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
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private async Task SeedAsync()
    {
        const string when = "2026-09-20 00:00:00";

        await using var db = new SqliteConnection($"Data Source={_dbPath}");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = $"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t1','local','Local','{when}','{when}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c1','t1','acme','Acme','{when}','{when}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d1','t1','c1','acme.com','{when}','{when}');
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,
               date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r1','t1','c1','d1','google.com','rep-1','{when}','{when}','h','{when}');
            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
              VALUES ('r1','t1','c1','d1','{when}','192.0.2.1',10,'pass'),
                     ('r1','t1','c1','d1','{when}','192.0.2.2',3,'fail');
            """;
        await command.ExecuteNonQueryAsync();
    }

    private BackupService Service() => new(_dbPath);

    // ---- the copy is a real database with the data in it ----------------------

    [Fact]
    public async Task WritesACopyThatHoldsTheData()
    {
        var result = await Service().RunAsync(_dir);

        Assert.NotNull(result.Path);
        Assert.True(File.Exists(result.Path));
        Assert.Equal(1, result.Reports);
        Assert.Equal(2, result.Records);
        Assert.True(result.Bytes > 0);
    }

    [Fact]
    public async Task TheCopyCanBeOpenedAndQueriedOnItsOwn()
    {
        // The property that makes it a backup rather than a file. Counted from
        // the copy, through a fresh connection, with the original untouched.
        var result = await Service().RunAsync(_dir);

        await using var db = new SqliteConnection($"Data Source={result.Path};Mode=ReadOnly");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT name FROM domains";

        Assert.Equal("acme.com", (string?)await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task TheSourceIsOpenedReadOnly()
    {
        // A backup must never be the thing that writes to a live database.
        var before = new FileInfo(_dbPath).LastWriteTimeUtc;
        await Service().RunAsync(_dir);

        Assert.Equal(before, new FileInfo(_dbPath).LastWriteTimeUtc);
    }

    [Fact]
    public async Task ACopyCanBeTakenWhileSomethingElseIsWriting()
    {
        // The whole reason this is VACUUM INTO rather than File.Copy: the
        // collector may be mid-write, and cp catches a torn page plus a -wal
        // that may not match it.
        await using var writer = new SqliteConnection($"Data Source={_dbPath}");
        await writer.OpenAsync();

        await using (var wal = writer.CreateCommand())
        {
            wal.CommandText = "PRAGMA journal_mode=WAL";
            await wal.ExecuteNonQueryAsync();
        }

        await using var tx = (SqliteTransaction)await writer.BeginTransactionAsync();
        await using (var insert = writer.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText =
                "INSERT INTO aggregate_records (report_id,tenant_id,client_id,domain_id,date_begin,"
                + "source_ip,message_count,dmarc_result) VALUES "
                + "('r1','t1','c1','d1','2026-09-20 00:00:00','192.0.2.9',1,'pass')";
            await insert.ExecuteNonQueryAsync();
        }

        // Uncommitted, so the snapshot must not contain it.
        var result = await Service().RunAsync(_dir);
        Assert.Equal(2, result.Records);

        await tx.CommitAsync();
    }

    // ---- a bad copy is never left looking like a good one ---------------------

    [Fact]
    public async Task ARunThatWouldOverwriteAnExistingBackupRefuses()
    {
        // Two runs in the same second must not silently leave one copy.
        var now = new DateTimeOffset(2026, 9, 22, 3, 20, 0, TimeSpan.Zero);

        await Service().RunAsync(_dir, now: now);

        await Assert.ThrowsAsync<IOException>(() => Service().RunAsync(_dir, now: now));
    }

    [Fact]
    public async Task AMissingDatabaseIsRefusedRatherThanBackedUpEmpty()
    {
        // Opening a SQLite path that is not there CREATES it, so without this
        // a typo in --db produces a perfectly valid backup of nothing.
        var absent = Path.Combine(Path.GetTempPath(), $"dmarc-absent-{Guid.NewGuid():N}.db");

        await Assert.ThrowsAsync<FileNotFoundException>(() => new BackupService(absent).RunAsync(_dir));

        Assert.False(File.Exists(absent));
    }

    // ---- retention ------------------------------------------------------------

    [Fact]
    public async Task KeepsOnlyTheNewestAndSaysWhatItRemoved()
    {
        var start = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

        for (var day = 0; day < 5; day++)
        {
            await Service().RunAsync(_dir, keep: 3, now: start.AddDays(day));
        }

        var left = Directory.GetFiles(_dir).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.Equal(3, left.Count);
        Assert.Equal(
            [BackupService.NameFor(start.AddDays(2)),
             BackupService.NameFor(start.AddDays(3)),
             BackupService.NameFor(start.AddDays(4))],
            left);
    }

    [Fact]
    public async Task RetentionLeavesFilesItDidNotWriteAlone()
    {
        // The directory is operator input. A sweep by age alone would delete
        // whatever else somebody had put beside the backups.
        Directory.CreateDirectory(_dir);
        var theirs = Path.Combine(_dir, "notes.txt");
        await File.WriteAllTextAsync(theirs, "not mine");

        var start = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        for (var day = 0; day < 4; day++)
        {
            await Service().RunAsync(_dir, keep: 1, now: start.AddDays(day));
        }

        Assert.True(File.Exists(theirs));
        Assert.Single(Directory.GetFiles(_dir, $"{BackupService.Prefix}*{BackupService.Extension}"));
    }

    [Fact]
    public async Task KeepingNoneIsRefused()
    {
        // A retention policy that can empty the directory is not one.
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Service().RunAsync(_dir, keep: 0));
    }

    [Fact]
    public async Task TheFirstBackupIsNeverPrunedByItsOwnRun()
    {
        var result = await Service().RunAsync(_dir, keep: 1);

        Assert.True(File.Exists(result.Path));
        Assert.Empty(result.Removed);
    }

    // ---- names ----------------------------------------------------------------

    [Fact]
    public void NamesSortLexicographicallyInTimeOrder()
    {
        // Retention sorts by name rather than by filesystem timestamp, because
        // a backup's whole purpose is to be copied somewhere else and mtimes
        // survive that badly.
        var earlier = BackupService.NameFor(new DateTimeOffset(2026, 9, 1, 3, 20, 0, TimeSpan.Zero));
        var later = BackupService.NameFor(new DateTimeOffset(2026, 9, 2, 3, 20, 0, TimeSpan.Zero));

        Assert.True(string.CompareOrdinal(earlier, later) < 0);
    }

    [Fact]
    public void ABackupIsNotNamedLikeADatabase()
    {
        // .bak rather than .db, so nothing points --db at one by accident and
        // starts collecting into a backup.
        var name = BackupService.NameFor(DateTimeOffset.UtcNow);

        Assert.EndsWith(".bak", name, StringComparison.Ordinal);
        Assert.DoesNotContain(".db", name, StringComparison.Ordinal);
    }

    [Fact]
    public void TheNameIsInUtcWhateverTheMachineIsSetTo()
    {
        var name = BackupService.NameFor(new DateTimeOffset(2026, 9, 22, 1, 0, 0, TimeSpan.FromHours(-7)));

        // 01:00 at UTC-7 is 08:00 UTC the same day.
        Assert.Equal("dmarc-20260922-080000.bak", name);
    }

    [Fact]
    public async Task ADirectoryThatDoesNotExistYetIsCreated()
    {
        var nested = Path.Combine(_dir, "deeper");
        var result = await new BackupService(_dbPath).RunAsync(nested);

        Assert.True(File.Exists(result.Path));
    }

    [Fact]
    public async Task RefusesAnEmptyDirectory()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Service().RunAsync("  "));
    }

    [Fact]
    public void RefusesAnEmptyDatabasePath()
    {
        Assert.Throws<ArgumentException>(() => new BackupService("  "));
    }
}
