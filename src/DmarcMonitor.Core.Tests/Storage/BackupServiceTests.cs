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

    // ---- the live database is checked BEFORE anything is written or removed ----
    //
    // Checking only the copy leaves the worse failure uncovered. A database
    // that has begun to corrupt still copies, and the copy verifies, because
    // it is a faithful copy of damaged pages. Fourteen nights later every
    // backup held is a copy of the damage and the last good one has been
    // pruned away, on schedule, by this service.

    /// <summary>Corrupts the source the way a bad disk would: by rewriting pages under it.</summary>
    /// <remarks>
    /// Two details are load-bearing, and both were found by getting them
    /// wrong. The WAL is checkpointed first, because rows written and not yet
    /// checkpointed live in the -wal file and leave the main database small -
    /// so an offset chosen in advance lands past its last real page, extends
    /// the file with zeroes, and is ignored. And the offset is computed from
    /// the file's actual size rather than fixed, so this damages a page that
    /// is genuinely in use whatever the seed happens to produce.
    /// </remarks>
    private async Task CorruptTheSourceAsync()
    {
        await using (var db = new SqliteConnection($"Data Source={_dbPath}"))
        {
            await db.OpenAsync();
            await using var command = db.CreateCommand();

            // Enough rows to span many pages, so there is a b-tree to damage
            // rather than only a header. A broken header fails to open at all,
            // which is a different and much louder failure than this is about.
            command.CommandText =
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 8000) "
                + "INSERT INTO aggregate_records "
                + "(report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result,header_from) "
                + "SELECT 'r1','t1','c1','d1','2026-09-20 00:00:00','192.0.2.1',1,'pass',"
                + "'padding-to-make-the-rows-wide-enough-to-span-pages' FROM n;"
                + "PRAGMA wal_checkpoint(TRUNCATE);";
            await command.ExecuteNonQueryAsync();
        }

        SqliteConnection.ClearAllPools();

        var size = new FileInfo(_dbPath).Length;
        Assert.True(size > 65536, $"the seed did not grow the database enough to damage ({size} bytes)");

        // Two thirds of the way in: past the header and the schema, inside
        // pages holding rows.
        await using var file = new FileStream(_dbPath, FileMode.Open, FileAccess.Write);
        file.Seek(size / 3 * 2, SeekOrigin.Begin);
        await file.WriteAsync(new byte[16384]);
        await file.FlushAsync();
    }

    [Fact]
    public async Task ACorruptDatabaseIsRefusedAndTheBackupsAlreadyHeldSurvive()
    {
        // The whole point. The good copy from before must still be there
        // afterwards, because it is the one somebody restores from.
        var good = await Service().RunAsync(_dir, keep: 1, now: new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.True(File.Exists(good.Path));

        await CorruptTheSourceAsync();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => Service().RunAsync(_dir, keep: 1, now: new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero)));

        // keep: 1 would have pruned it had the run got that far.
        Assert.True(File.Exists(good.Path));
        Assert.Single(Directory.GetFiles(_dir, $"{BackupService.Prefix}*{BackupService.Extension}"));
    }

    [Fact]
    public async Task ACorruptDatabaseWritesNoCopyAtAll()
    {
        // A copy of a corrupt database is not evidence worth the risk of
        // somebody later mistaking it for a backup.
        await CorruptTheSourceAsync();

        var when = new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero);
        await Assert.ThrowsAsync<InvalidDataException>(() => Service().RunAsync(_dir, now: when));

        Assert.False(File.Exists(Path.Combine(_dir, BackupService.NameFor(when))));
    }

    [Fact]
    public async Task TheRefusalSaysTheBackupsAreUntouched()
    {
        // Read at 03:20 by somebody who has just been paged. It has to say
        // what is safe, not only what is wrong.
        await CorruptTheSourceAsync();

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => Service().RunAsync(_dir));

        Assert.Contains("nothing was removed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AHealthyDatabasePassesBothChecks()
    {
        // The boundary from the quiet side: the ordinary nightly run must not
        // start refusing because a check was added.
        var result = await Service().RunAsync(_dir);

        Assert.NotNull(result.Path);
        Assert.Equal(2, result.Records);
    }

    [Fact]
    public async Task TheQuickCheckAlsoRefusesACorruptDatabase()
    {
        await CorruptTheSourceAsync();

        await Assert.ThrowsAsync<InvalidDataException>(() => Service().RunAsync(_dir, quick: true));
    }

    [Fact]
    public async Task AnOrphanedRecordIsRefusedEvenThoughThePagesAreFine()
    {
        // Not page corruption - data that has lost its meaning. A record
        // pointing at a report that is no longer there passes integrity_check
        // completely, and is worth knowing before it is copied forward another
        // fourteen nights.
        await using (var db = new SqliteConnection($"Data Source={_dbPath}"))
        {
            await db.OpenAsync();

            // Foreign keys off, so the delete leaves the child behind rather
            // than cascading - which is exactly the state a partial restore or
            // a hand-edited database arrives in.
            await using var command = db.CreateCommand();
            command.CommandText = "PRAGMA foreign_keys=OFF; DELETE FROM aggregate_reports WHERE id = 'r1';";
            await command.ExecuteNonQueryAsync();
        }

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => Service().RunAsync(_dir));

        Assert.Contains("aggregate_records", ex.Message, StringComparison.Ordinal);
    }

    // ---- a backup is a complete copy of every client's data --------------------

    [Fact]
    public async Task ABackupIsReadableByItsOwnerAndNobodyElse()
    {
        // This was 0644 in a 0755 directory, because VACUUM INTO takes whatever
        // the umask gives it. The live database is 0600 - so taking a backup
        // silently DOWNGRADED the protection on the data, every night, on a
        // timer. Any local account on the box could read a full copy.
        if (OperatingSystem.IsWindows()) { return; }   // no mode to check

        var result = await Service().RunAsync(_dir);

        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(result.Path!));
    }

    [Fact]
    public async Task TheBackupDirectoryIsNotTraversableByOthers()
    {
        // The file mode is set after VACUUM INTO has created it, so there is a
        // window of milliseconds where it exists at 0644. The directory being
        // 0700 is what actually closes that window, which is why it is set
        // before anything is written into it.
        if (OperatingSystem.IsWindows()) { return; }

        await Service().RunAsync(_dir);

        var mode = File.GetUnixFileMode(_dir);

        Assert.False(mode.HasFlag(UnixFileMode.GroupRead), "the group can read the backup directory");
        Assert.False(mode.HasFlag(UnixFileMode.OtherRead), "anybody can read the backup directory");
        Assert.False(mode.HasFlag(UnixFileMode.OtherExecute), "anybody can traverse into the backup directory");
    }

    [Fact]
    public async Task ADirectoryTheOperatorAlreadyMadeIsTightenedToo()
    {
        // Pointed at somewhere that already exists - another disk, a mount -
        // the permissions are still brought down. An operator who made the
        // directory with `mkdir` got 0755 and no warning.
        if (OperatingSystem.IsWindows()) { return; }

        Directory.CreateDirectory(_dir);
        File.SetUnixFileMode(_dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                 | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                 | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);   // 0755

        await Service().RunAsync(_dir);

        Assert.False(File.GetUnixFileMode(_dir).HasFlag(UnixFileMode.OtherRead));
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
