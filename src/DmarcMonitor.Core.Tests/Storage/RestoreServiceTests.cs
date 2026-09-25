using System.IO.Compression;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// Putting a backup back: dmarc restore.
/// </summary>
/// <remarks>
/// Restores happen after something has gone wrong, by somebody under pressure,
/// so the properties that matter are about what cannot happen: nothing live is
/// touched until the whole backup has been checked, what was in place is kept
/// rather than overwritten, a write-ahead log never lands on the wrong
/// database, and a zip entry never writes outside the folder it belongs in.
/// </remarks>
public sealed class RestoreServiceTests : IDisposable
{
    private const string When = "2026-09-20 00:00:00";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"dmarc-restore-{Guid.NewGuid():N}");
    private readonly string _dbPath;
    private readonly string _backups;

    public RestoreServiceTests()
    {
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "dmarc.db");
        _backups = Path.Combine(_dir, "backups");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private ClientDatabases Files => new(_dbPath);

    /// <summary>Two clients with reports, split into their files, and a backup of that.</summary>
    private async Task<string> BackedUpAsync()
    {
        await new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql);
        await SingleDatabase.ExecuteAsync(_dbPath, $"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at) VALUES ('t1','nrg','NRG','{When}','{When}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c1','t1','acme','Acme','{When}','{When}'), ('c2','t1','globex','Globex','{When}','{When}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d1','t1','c1','acme.com','{When}','{When}'), ('d2','t1','c2','globex.com','{When}','{When}');
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r1','t1','c1','d1','google.com','rep-1','{When}','{When}','h1','{When}'),
                     ('r2','t1','c2','d2','google.com','rep-2','{When}','{When}','h2','{When}');
            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
              VALUES ('r1','t1','c1','d1','{When}','192.0.2.1',10,'pass'),
                     ('r1','t1','c1','d1','{When}','192.0.2.2',3,'fail'),
                     ('r2','t1','c2','d2','{When}','192.0.2.7',5,'pass');
            """);

        var backup = await new BackupService(_dbPath).RunAsync(_backups);
        SqliteConnection.ClearAllPools();
        return backup.Path!;
    }

    private Task<long> RecordsAsync() => SingleDatabase.CountAsync(_dbPath, "SELECT COUNT(*) FROM aggregate_records");

    /// <summary>What happened after the backup was taken: one client erased, a report for the other.</summary>
    private async Task SomethingHappensAsync()
    {
        Assert.NotNull(await new ClientErasure(_dbPath).ApplyAsync("globex", null, "test", null));
        await SingleDatabase.ExecuteAsync(_dbPath, $"""
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r3','t1','c1','d1','google.com','rep-3','{When}','{When}','h3','{When}');
            INSERT INTO aggregate_records
              (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
              VALUES ('r3','t1','c1','d1','{When}','192.0.2.9',1,'pass');
            """);
        SqliteConnection.ClearAllPools();
    }

    private static string Zip(string path, params (string Name, string? From)[] entries)
    {
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, from) in entries)
        {
            if (from is null) { zip.CreateEntry(name); }
            else { zip.CreateEntryFromFile(from, name); }
        }
        return path;
    }

    // ---- putting it back -----------------------------------------------------

    [Fact]
    public async Task ItReadsBackExactlyWhatWasBackedUp()
    {
        var backup = await BackedUpAsync();
        await SomethingHappensAsync();
        Assert.Equal(3, await RecordsAsync());   // 2 of Acme's + the new one; Globex's gone

        var result = await new RestoreService(_dbPath).RunAsync(backup);

        Assert.Equal(2, result.ClientFiles);
        Assert.Equal(2, result.Reports);
        Assert.Equal(3, result.Records);
        Assert.Equal(1, await SingleDatabase.CountAsync(_dbPath, "SELECT COUNT(*) FROM clients WHERE slug = 'globex'"));
        Assert.Equal(1, await SingleDatabase.CountAsync(_dbPath, "SELECT COUNT(*) FROM aggregate_records WHERE client_id = 'c2'"));
        Assert.Equal(0, await SingleDatabase.CountAsync(_dbPath, "SELECT COUNT(*) FROM aggregate_reports WHERE id = 'r3'"));
    }

    [Fact]
    public async Task WhatWasInPlaceIsKeptBesideIt()
    {
        // Everything since the backup is in it, and nowhere else.
        var backup = await BackedUpAsync();
        await SomethingHappensAsync();

        var result = await new RestoreService(_dbPath).RunAsync(backup);

        Assert.NotNull(result.Replaced);
        Assert.NotNull(result.ReplacedClients);
        Assert.Equal(ClientDatabases.FolderFor(result.Replaced), result.ReplacedClients);
        Assert.Equal(1, await SingleDatabase.CountAsync(result.Replaced, "SELECT COUNT(*) FROM aggregate_reports WHERE id = 'r3'"));
        Assert.Equal(0, await SingleDatabase.CountAsync(result.Replaced, "SELECT COUNT(*) FROM clients WHERE slug = 'globex'"));
    }

    /// <summary>
    /// The mistake the old instructions spent a paragraph on: a -wal left
    /// beside a restored file is replayed onto it. It belongs to the database
    /// being replaced, and goes with it - its transactions end up there, and
    /// not in what was restored.
    /// </summary>
    [Fact]
    public async Task TheReplacedDatabasesJournalGoesWithIt()
    {
        var backup = await BackedUpAsync();

        // A crash: a transaction committed to the write-ahead log and never
        // checkpointed into the file, which is the state a restore after a
        // failure usually starts from.
        var crash = Path.Combine(_dir, "crash");
        Directory.CreateDirectory(crash);
        await using (var db = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            await db.OpenAsync();
            await using (var command = db.CreateCommand())
            {
                command.CommandText = $"""
                    PRAGMA wal_autocheckpoint = 0;
                    INSERT INTO tenants (id,slug,name,created_at,updated_at)
                      VALUES ('t-wal','walonly','Only in the log','{When}','{When}');
                    """;
                await command.ExecuteNonQueryAsync();
            }
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                File.Copy(_dbPath + suffix, Path.Combine(crash, "db" + suffix));
            }
        }
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            File.Copy(Path.Combine(crash, "db" + suffix), _dbPath + suffix, overwrite: true);
        }
        Assert.True(new FileInfo(_dbPath + "-wal").Length > 0);

        var result = await new RestoreService(_dbPath).RunAsync(backup);

        Assert.Equal(0, await SingleDatabase.CountAsync(_dbPath, "SELECT COUNT(*) FROM tenants WHERE id = 't-wal'"));
        Assert.Equal(1, await SingleDatabase.CountAsync(result.Replaced!, "SELECT COUNT(*) FROM tenants WHERE id = 't-wal'"));
    }

    [Fact]
    public async Task ItRestoresOntoAMachineWithNothingThereYet()
    {
        var backup = await BackedUpAsync();
        var elsewhere = Path.Combine(_dir, "new-machine", "dmarc.db");

        var result = await new RestoreService(elsewhere).RunAsync(backup);

        Assert.Null(result.Replaced);
        Assert.Equal(3, await SingleDatabase.CountAsync(elsewhere, "SELECT COUNT(*) FROM aggregate_records"));
    }

    /// <summary>
    /// A backup taken before each client had a file of its own is one SQLite
    /// database. It restores, and is split on the way in.
    /// </summary>
    [Fact]
    public async Task ABackupFromBeforeTheSplitIsSplitOnTheWayIn()
    {
        var old = Path.Combine(_dir, "dmarc-20260901-032000.bak");
        await using (var db = new SqliteConnection($"Data Source={old};Pooling=False"))
        {
            await db.OpenAsync();
            await using var command = db.CreateCommand();
            command.CommandText = SingleDatabase.Schema + $"""

                INSERT INTO tenants (id,slug,name,created_at,updated_at) VALUES ('t1','nrg','NRG','{When}','{When}');
                INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at) VALUES ('c1','t1','acme','Acme','{When}','{When}');
                INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at) VALUES ('d1','t1','c1','acme.com','{When}','{When}');
                INSERT INTO aggregate_reports
                  (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
                  VALUES ('r1','t1','c1','d1','google.com','rep-1','{When}','{When}','h1','{When}');
                INSERT INTO aggregate_records
                  (report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
                  VALUES ('r1','t1','c1','d1','{When}','192.0.2.1',10,'pass');
                """;
            await command.ExecuteNonQueryAsync();
        }
        SqliteConnection.ClearAllPools();

        var result = await new RestoreService(_dbPath).RunAsync(old);

        Assert.NotNull(result.Migration.Split);
        Assert.Equal(1, result.ClientFiles);
        Assert.Equal(1, result.Records);
        Assert.True(File.Exists(Files.PathFor(new ClientFile("c1", "acme", "t1"))));
    }

    // ---- refusing, with nothing touched ------------------------------------------

    [Fact]
    public async Task AnEntryThatWouldWriteOutsideTheFolderIsRefusedAndNothingIsTouched()
    {
        var backup = await BackedUpAsync();
        var records = await RecordsAsync();
        var unpacked = Path.Combine(_dir, "unpacked");
        ZipFile.ExtractToDirectory(backup, unpacked);

        foreach (var evil in new[] { "../escaped.db", "dmarc-clients/../../escaped.db", "..\\escaped.db", "/tmp/escaped.db", "c:/escaped.db" })
        {
            var crafted = Zip(Path.Combine(_dir, $"crafted-{Guid.NewGuid():N}.bak"),
                ("dmarc.db", Path.Combine(unpacked, "dmarc.db")),
                (evil, Path.Combine(unpacked, "dmarc.db")));

            await Assert.ThrowsAsync<InvalidDataException>(() => new RestoreService(_dbPath).RunAsync(crafted));

            Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(_dir)!, "escaped.db")));
            Assert.False(File.Exists(Path.Combine(_dir, "escaped.db")));
            Assert.Equal(records, await RecordsAsync());
        }

        // And nothing half-unpacked was left beside the database.
        Assert.Empty(Directory.GetDirectories(_dir, "dmarc.restoring-*"));
    }

    [Fact]
    public async Task ADamagedFileInTheBackupIsRefusedAndNothingIsTouched()
    {
        var backup = await BackedUpAsync();
        var records = await RecordsAsync();
        var unpacked = Path.Combine(_dir, "unpacked");
        ZipFile.ExtractToDirectory(backup, unpacked);

        var client = Directory.GetFiles(Path.Combine(unpacked, "dmarc-clients"), "*.db")[0];
        var bytes = await File.ReadAllBytesAsync(client);
        Array.Fill(bytes, (byte)0xAB, 4096, Math.Min(4096, bytes.Length - 4096));   // the second page
        var damaged = Path.Combine(_dir, "damaged.db");
        await File.WriteAllBytesAsync(damaged, bytes);

        var crafted = Zip(Path.Combine(_dir, "crafted.bak"),
            ("dmarc.db", Path.Combine(unpacked, "dmarc.db")),
            ("dmarc-clients/" + Path.GetFileName(client), damaged));

        await Assert.ThrowsAsync<InvalidDataException>(() => new RestoreService(_dbPath).RunAsync(crafted));

        Assert.Equal(records, await RecordsAsync());
        Assert.Empty(Directory.GetFiles(_dir, "dmarc-replaced-*"));
    }

    [Fact]
    public async Task SomethingThatIsNotABackupIsRefused()
    {
        await BackedUpAsync();
        var notes = Path.Combine(_dir, "notes.bak");
        await File.WriteAllTextAsync(notes, "this is not a backup");

        var refused = await Assert.ThrowsAsync<InvalidDataException>(() => new RestoreService(_dbPath).RunAsync(notes));
        Assert.Contains("not a backup this product wrote", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADatabaseThatIsNotOursIsRefused()
    {
        await BackedUpAsync();
        var theirs = Path.Combine(_dir, "theirs.db");
        await using (var db = new SqliteConnection($"Data Source={theirs};Pooling=False"))
        {
            await db.OpenAsync();
            await using var command = db.CreateCommand();
            command.CommandText = "CREATE TABLE notes (body TEXT)";
            await command.ExecuteNonQueryAsync();
        }
        SqliteConnection.ClearAllPools();

        await Assert.ThrowsAsync<InvalidDataException>(() => new RestoreService(_dbPath).RunAsync(theirs));
        Assert.Equal(3, await RecordsAsync());
    }

    /// <summary>
    /// A collector part way through a report would go on writing into the file
    /// after it was moved aside, and the report would be in neither.
    /// </summary>
    [Fact]
    public async Task ItWillNotRestoreOverADatabaseBeingWrittenTo()
    {
        var backup = await BackedUpAsync();

        await using var writer = new SqliteConnection($"Data Source={_dbPath};Pooling=False");
        await writer.OpenAsync();
        await using var tx = writer.BeginTransaction(deferred: false);

        await Assert.ThrowsAsync<IOException>(() => new RestoreService(_dbPath).RunAsync(backup));
        Assert.Empty(Directory.GetFiles(_dir, "dmarc-replaced-*"));
    }
}
