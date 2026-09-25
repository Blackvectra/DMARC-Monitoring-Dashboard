using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// One database file per client: the upgrade that splits an existing database,
/// the wall between one client's file and another's, and what init-db puts
/// right when a process stopped between two files.
/// </summary>
/// <remarks>
/// The upgrade is the one migration that moves customers' data rather than
/// adding somewhere to put it, so most of what is below is about what it must
/// not lose, and where what it cannot place goes instead of away.
/// </remarks>
public sealed class ClientFilesTests : IDisposable
{
    private const string When = "2026-09-20 00:00:00";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-files-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SingleDatabase.Delete(_dbPath);

        var folder = ClientDatabases.FolderFor(_dbPath);
        foreach (var aside in Directory.EnumerateDirectories(
            Path.GetDirectoryName(folder)!, Path.GetFileName(folder) + ".set-aside-*"))
        {
            try { Directory.Delete(aside, recursive: true); } catch (IOException) { }
        }
    }

    /// <summary>
    /// Two organizations and four clients, one of them with nothing stored,
    /// in one database as the release before the split left it.
    /// </summary>
    private async Task OlderDatabaseAsync(string extra = "")
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath};Pooling=False");
        await db.OpenAsync();
        await ExecuteAsync(db, SingleDatabase.Schema);
        await ExecuteAsync(db, $"""
            INSERT INTO tenants (id,slug,name,created_at,updated_at)
              VALUES ('t-a','orga','Org A','{When}','{When}'),('t-b','orgb','Org B','{When}','{When}');
            INSERT INTO clients (id,tenant_id,slug,name,created_at,updated_at)
              VALUES ('c-a','t-a','acme','Acme Corp','{When}','{When}'),
                     ('c-other','t-a','beta','Beta Ltd','{When}','{When}'),
                     ('c-b','t-b','gamma','Gamma Inc','{When}','{When}'),
                     ('c-quiet','t-a','quiet','Quiet Co','{When}','{When}');
            INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
              VALUES ('d-a','t-a','c-a','acme.com','{When}','{When}'),
                     ('d-other','t-a','c-other','beta.example','{When}','{When}'),
                     ('d-b','t-b','c-b','gamma.example','{When}','{When}');

            INSERT INTO senders (id,tenant_id,client_id,source_ip,first_seen,last_seen,created_at,updated_at)
              VALUES ('snd-a','t-a','c-a','192.0.2.1','{When}','{When}','{When}','{When}');

            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r-a','t-a','c-a','d-a','google.com','ra','{When}','{When}','ha','{When}'),
                     ('r-other','t-a','c-other','d-other','google.com','ro','{When}','{When}','ho','{When}'),
                     ('r-b','t-b','c-b','d-b','google.com','rb','{When}','{When}','hb','{When}');

            INSERT INTO aggregate_records
              (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result,sender_id)
              VALUES (10,'r-a','t-a','c-a','d-a','{When}','192.0.2.1',10,'pass','snd-a'),
                     (11,'r-a','t-a','c-a','d-a','{When}','192.0.2.2',5,'fail',NULL),
                     (12,'r-other','t-a','c-other','d-other','{When}','198.51.100.1',7,'pass',NULL),
                     (40,'r-b','t-b','c-b','d-b','{When}','203.0.113.1',3,'fail',NULL);

            INSERT INTO forensic_reports (id,tenant_id,client_id,domain_id,source_ip,received_at,ingested_at)
              VALUES (7,'t-b','c-b','d-b','203.0.113.1','{When}','{When}');
            """ + extra);
    }

    private async Task<MigrationResult> UpgradeAsync()
    {
        SqliteConnection.ClearAllPools();
        return await DatabaseMigrations.ApplyAsync(_dbPath);
    }

    private ClientDatabases Files => new(_dbPath);

    private string FileOf(string clientId, string slug, string tenantId) =>
        Files.PathFor(new ClientFile(clientId, slug, tenantId));

    /// <summary>A count read straight out of one file, with nothing else attached.</summary>
    private static async Task<long> CountInAsync(string path, string sql)
    {
        await using var db = new SqliteConnection($"Data Source={path};Mode=ReadOnly;Pooling=False");
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0L);
    }

    private static async Task<long> CountAsync(SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0L);
    }

    private static async Task ExecuteAsync(SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private async Task InRegistryAsync(string sql)
    {
        await using var db = new SqliteConnection($"Data Source={_dbPath};Pooling=False");
        await db.OpenAsync();
        await ExecuteAsync(db, sql);
    }

    private async Task<long> NextIdAsync(string table) => await Files.NextIdAsync(table);

    // ---- the upgrade ----------------------------------------------------------

    [Fact]
    public async Task EveryClientsRowsLandInTheirOwnFileAndNowhereElse()
    {
        await OlderDatabaseAsync();

        var result = await UpgradeAsync();

        var split = Assert.IsType<SplitResult>(result.Split);
        Assert.Equal(3, split.Files);
        Assert.Equal(0, split.Unfiled);

        var acme = FileOf("c-a", "acme", "t-a");
        var beta = FileOf("c-other", "beta", "t-a");
        var gamma = FileOf("c-b", "gamma", "t-b");

        Assert.Equal(2, await CountInAsync(acme, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(1, await CountInAsync(acme, "SELECT COUNT(*) FROM aggregate_reports"));
        Assert.Equal(1, await CountInAsync(acme, "SELECT COUNT(*) FROM senders"));
        Assert.Equal(1, await CountInAsync(beta, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(1, await CountInAsync(gamma, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(1, await CountInAsync(gamma, "SELECT COUNT(*) FROM forensic_reports"));

        // Nothing in any file that is not that file's client's.
        foreach (var (path, id) in new[] { (acme, "c-a"), (beta, "c-other"), (gamma, "c-b") })
        {
            foreach (var table in ClientDatabases.Tables)
            {
                Assert.Equal(0, await CountInAsync(path, $"SELECT COUNT(*) FROM {table} WHERE client_id <> '{id}'"));
            }
        }

        // And a reference inside a file still points at its row.
        Assert.Equal(1, await CountInAsync(acme,
            "SELECT COUNT(*) FROM aggregate_records r JOIN senders s ON s.id = r.sender_id"));
    }

    [Fact]
    public async Task EveryRowIsCountedAndTheTotalsAgree()
    {
        await OlderDatabaseAsync();

        var split = (await UpgradeAsync()).Split!;

        // 1 sender + 3 reports + 4 records + 1 failure report.
        Assert.Equal(9, split.Rows);
        Assert.Equal(9, await SingleDatabase.CountAsync(_dbPath, """
            SELECT (SELECT COUNT(*) FROM senders) + (SELECT COUNT(*) FROM aggregate_reports)
                 + (SELECT COUNT(*) FROM aggregate_records) + (SELECT COUNT(*) FROM forensic_reports)
            """));
    }

    [Fact]
    public async Task TheOrganizationsDatabaseNoLongerHoldsAnyonesMail()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        foreach (var table in ClientDatabases.Tables)
        {
            Assert.Equal(0, await CountInAsync(_dbPath,
                $"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '{table}'"));
        }

        // What the organization owns stays: its clients and their domains.
        Assert.Equal(4, await CountInAsync(_dbPath, "SELECT COUNT(*) FROM clients"));
        Assert.Equal(3, await CountInAsync(_dbPath, "SELECT COUNT(*) FROM domains"));
        Assert.Equal(ClientFileSplit.Version, await DatabaseMigrations.VersionAsync(_dbPath));
    }

    [Fact]
    public async Task TheRowsKeepTheirIdsAndTheSequenceCarriesOnFromTheLargest()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        Assert.Equal(21, await CountInAsync(FileOf("c-a", "acme", "t-a"), "SELECT SUM(id) FROM aggregate_records"));
        Assert.Equal(40, await CountInAsync(FileOf("c-b", "gamma", "t-b"), "SELECT id FROM aggregate_records"));

        // Unique across every file, so the next is past the largest anywhere,
        // not the largest in any one file.
        Assert.Equal(41, await NextIdAsync("aggregate_records"));
        Assert.Equal(8, await NextIdAsync("forensic_reports"));
        Assert.Equal(1, await NextIdAsync("tls_failure_details"));
    }

    [Fact]
    public async Task TheDatabaseAsItWasIsKeptBesideIt()
    {
        await OlderDatabaseAsync();

        var split = (await UpgradeAsync()).Split!;

        Assert.Equal(
            Path.Combine(Path.GetDirectoryName(Path.GetFullPath(_dbPath))!,
                Path.GetFileNameWithoutExtension(_dbPath) + ".pre-0019.db"),
            split.Backup);
        Assert.Equal(4, await CountInAsync(split.Backup, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal("0018", (await CountInAsync(split.Backup,
            "SELECT MAX(CAST(version AS INTEGER)) FROM schema_migrations")).ToString("0000", System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task AClientWithNothingStoredGetsNoFileUntilSomethingIs()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        Assert.False(File.Exists(FileOf("c-quiet", "quiet", "t-a")));

        // And reads as a client with no mail, not as an error.
        await using var db = await Files.OpenAsync(ClientScope.Client("c-quiet"));
        Assert.Equal(0, await CountAsync(db, "SELECT COUNT(*) FROM aggregate_records"));
    }

    [Fact]
    public async Task RowsWhoseClientIsGoneAreKeptInAFileOfTheirOwn()
    {
        // Never written by this product - client_id is a foreign key - but a
        // database edited by hand is not somewhere to lose rows on the way past.
        await OlderDatabaseAsync($"""
            PRAGMA foreign_keys = OFF;
            INSERT INTO aggregate_reports
              (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,ingested_at)
              VALUES ('r-gone','t-a','c-gone','d-gone','google.com','rg','{When}','{When}','hg','{When}');
            INSERT INTO aggregate_records
              (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
              VALUES (50,'r-gone','t-a','c-gone','d-gone','{When}','192.0.2.9',1,'pass');
            """);

        var split = (await UpgradeAsync()).Split!;

        Assert.Equal(2, split.Unfiled);
        var unfiled = Path.Combine(Files.Folder, "unfiled-rows.db");
        Assert.Equal(50, await CountInAsync(unfiled, "SELECT id FROM aggregate_records"));
        Assert.Equal(51, await NextIdAsync("aggregate_records"));
    }

    [Fact]
    public async Task AFolderLeftByAnInterruptedAttemptIsMovedAsideNotDeleted()
    {
        await OlderDatabaseAsync();
        Directory.CreateDirectory(Files.Folder);
        await File.WriteAllTextAsync(Path.Combine(Files.Folder, "left-behind.db"), "from an attempt that stopped");

        var split = (await UpgradeAsync()).Split!;

        Assert.NotNull(split.SetAside);
        Assert.True(File.Exists(Path.Combine(split.SetAside, "left-behind.db")));
        Assert.False(File.Exists(Path.Combine(Files.Folder, "left-behind.db")));
        Assert.Equal(2, await CountInAsync(FileOf("c-a", "acme", "t-a"), "SELECT COUNT(*) FROM aggregate_records"));
    }

    [Fact]
    public async Task ASecondRunChangesNothing()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();
        var files = Directory.GetFiles(Files.Folder).Order(StringComparer.Ordinal).ToList();

        var again = await UpgradeAsync();

        Assert.Empty(again.Applied);
        Assert.Null(again.Split);
        Assert.Equal(files, Directory.GetFiles(Files.Folder).Order(StringComparer.Ordinal).ToList());
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(Path.GetFullPath(_dbPath))!,
            Path.GetFileNameWithoutExtension(_dbPath) + ".pre-0019*"));
    }

    [Fact]
    public async Task ADatabaseNotYetSplitIsRefusedRatherThanShownEmpty()
    {
        // Every page would open against client files that do not exist yet,
        // and show a customer base that has never sent mail.
        await OlderDatabaseAsync();

        var refused = await Assert.ThrowsAsync<DatabaseNotSplitException>(
            () => Files.OpenAsync(ClientScope.Organization(null)));

        Assert.Equal("0018", refused.Version);
        Assert.Contains("init-db", refused.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every client's mail is in that folder. The umask would leave it 0755
    /// with each file 0644, readable by any account that can reach it.
    /// </summary>
    [Fact]
    public async Task ClientFilesAreReadableByTheirOwnerAlone()
    {
        if (OperatingSystem.IsWindows()) { return; }

        await OlderDatabaseAsync();
        await UpgradeAsync();

        // And a file made later, for a client created after the upgrade.
        Assert.NotNull(await new ReportStore(_dbPath, "orga").CreateClientAsync("Late Arrival"));

        const UnixFileMode folder = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        const UnixFileMode file = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        Assert.Equal(folder, File.GetUnixFileMode(Files.Folder));
        var files = Directory.GetFiles(Files.Folder, "*.db");
        Assert.Equal(4, files.Length);
        foreach (var path in files) { Assert.Equal(file, File.GetUnixFileMode(path)); }
    }

    /// <summary>
    /// The copy the upgrade keeps is every client's data as it was, and
    /// nothing prunes it. Whatever says a client's data is gone says so.
    /// </summary>
    [Fact]
    public async Task ErasingAClientNamesTheWholeCopiesThatStillHoldIt()
    {
        await OlderDatabaseAsync();
        var split = (await UpgradeAsync()).Split!;

        var erased = await new ClientErasure(_dbPath).ApplyAsync("acme", "t-a", "test", null);

        Assert.NotNull(erased);
        Assert.Equal([split.Backup], erased.OtherCopies);
    }

    [Fact]
    public void TheCopiesBesideADatabaseAreTheOnesThisProductKeeps()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"dmarc-copies-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            string[] ours =
            [
                "dmarc.pre-0019.db", "dmarc-20260925-170601.db", "dmarc-20260925-170601-clients",
                "dmarc-replaced-20260925-170601.db", "dmarc-replaced-20260925-170601-clients",
                "dmarc-clients.set-aside-20260925-170601",
            ];
            string[] notOurs =
            [
                "dmarc.db", "dmarc.db-wal", "dmarc-clients", "dmarc-replaced-20260925-170601.db-wal",
                "dmarc-notes.db", "dmarc-2026.db", "other-20260925-170601.db", "dmarcx.pre-0019.db",
            ];
            foreach (var entry in ours.Concat(notOurs))
            {
                if (entry.EndsWith("-clients", StringComparison.Ordinal) || entry.Contains(".set-aside-", StringComparison.Ordinal))
                {
                    Directory.CreateDirectory(Path.Combine(dir, entry));
                }
                else
                {
                    File.WriteAllText(Path.Combine(dir, entry), "");
                }
            }

            var found = ClientDatabases.CopiesBeside(Path.Combine(dir, "dmarc.db")).Select(Path.GetFileName);

            Assert.Equal(ours.Order(StringComparer.Ordinal), found);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- the wall between files ------------------------------------------------

    [Fact]
    public async Task OneClientsConnectionCannotReadAnotherClientsMail()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        await using var db = await Files.OpenAsync(ClientScope.Client("c-a"));

        // No WHERE clause at all: the only rows there are to read are Acme's.
        Assert.Equal(2, await CountAsync(db, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(0, await CountAsync(db, "SELECT COUNT(*) FROM aggregate_records WHERE client_id <> 'c-a'"));
        Assert.Equal(0, await CountAsync(db, "SELECT COUNT(*) FROM forensic_reports"));
    }

    [Fact]
    public async Task AnOrganizationsConnectionSeesOnlyItsOwnClients()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        await using var db = await Files.OpenAsync(ClientScope.Organization("t-a"));

        Assert.Equal(3, await CountAsync(db, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(0, await CountAsync(db, "SELECT COUNT(*) FROM aggregate_records WHERE tenant_id <> 't-a'"));
    }

    /// <summary>
    /// A union is TEMP tables on its connection, and TEMP is searched before
    /// an attached file. A pooled handle carrying one into the next caller's
    /// hands would show a customer's login every client's mail.
    /// </summary>
    [Fact]
    public async Task AUnionLeavesNothingBehindForTheNextConnection()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        for (var i = 0; i < 3; i++)
        {
            await using (var everyone = await Files.OpenAsync(ClientScope.Organization(null)))
            {
                Assert.Equal(4, await CountAsync(everyone, "SELECT COUNT(*) FROM aggregate_records"));
            }

            await using var one = await Files.OpenAsync(ClientScope.Client("c-other"));
            Assert.Equal(1, await CountAsync(one, "SELECT COUNT(*) FROM aggregate_records"));
            Assert.Equal(0, await CountAsync(one, "SELECT COUNT(*) FROM temp.sqlite_master"));
        }
    }

    [Fact]
    public async Task AFileCopiedIntoAnotherClientsPlaceIsNotReadAsTheirs()
    {
        // By hand, from a backup, or by a bug in naming: either way, Beta's
        // login must not be shown Acme's mail because a file has Beta's name.
        await OlderDatabaseAsync();
        await UpgradeAsync();
        SqliteConnection.ClearAllPools();
        File.Copy(FileOf("c-a", "acme", "t-a"), FileOf("c-other", "beta", "t-a"), overwrite: true);

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Files.OpenAsync(ClientScope.Client("c-other")));

        Assert.Contains("belongs to client c-a", refused.Message, StringComparison.Ordinal);
    }

    // ---- putting the files right ---------------------------------------------------

    /// <summary>
    /// A domain filed under another client is committed in the organization's
    /// database first and its rows moved second. A process stopped between the
    /// two leaves the rows in the file of a client that no longer has the
    /// domain - so the new client's report is empty and the old one's is not.
    /// </summary>
    [Fact]
    public async Task AMoveThatStoppedHalfWayIsFinishedByReconcile()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();
        await InRegistryAsync("UPDATE domains SET client_id = 'c-other' WHERE id = 'd-a'");

        var repaired = await Files.ReconcileAsync();

        Assert.Equal(["d-a: acme -> beta"], repaired.MovedDomains);
        Assert.Equal(0, await CountInAsync(FileOf("c-a", "acme", "t-a"), "SELECT COUNT(*) FROM aggregate_records"));

        var beta = FileOf("c-other", "beta", "t-a");
        Assert.Equal(3, await CountInAsync(beta, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(0, await CountInAsync(beta, "SELECT COUNT(*) FROM aggregate_records WHERE client_id <> 'c-other'"));
        Assert.Equal(22, await CountInAsync(beta, "SELECT SUM(message_count) FROM aggregate_records"));

        // And a second run finds nothing to do.
        Assert.False((await Files.ReconcileAsync()).Changed);
    }

    /// <summary>
    /// The organization's database put back from a copy older than the client
    /// files: its row id sequence is behind the ids already stored.
    /// </summary>
    [Fact]
    public async Task ASequenceBehindTheFilesIsPutPastThem()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();
        await InRegistryAsync("UPDATE row_ids SET next_id = 1");

        var repaired = await Files.ReconcileAsync();

        Assert.True(repaired.Changed);
        Assert.Contains(repaired.RaisedSequences, r => r.StartsWith("aggregate_records", StringComparison.Ordinal));
        Assert.Contains(repaired.RaisedSequences, r => r.StartsWith("forensic_reports", StringComparison.Ordinal));
        Assert.Equal(41, await NextIdAsync("aggregate_records"));
        Assert.Equal(8, await NextIdAsync("forensic_reports"));

        // Never lowered: a sequence already ahead stays where it is.
        Assert.Empty((await Files.ReconcileAsync()).RaisedSequences);
    }

    /// <summary>
    /// And until init-db has run: a report arriving at a file whose ids the
    /// sequence has fallen behind must still be stored. Before, it took an id
    /// the file already held, and every report for that client failed.
    /// </summary>
    [Fact]
    public async Task ANewReportNeverTakesAnIdItsFileAlreadyHolds()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();
        await InRegistryAsync("UPDATE row_ids SET next_id = 1");

        var store = new ReportStore(_dbPath, "orga");
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>test.example</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}</begin>
                            <end>{DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p><pct>100</pct></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.5</source_ip><count>12</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results><spf><domain>acme.com</domain><result>pass</result></spf></auth_results>
              </record>
            </feedback>
            """;
        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);

        Assert.NotNull(await store.SaveAggregateAsync(parsed.Report!, xml, null));

        var acme = FileOf("c-a", "acme", "t-a");
        Assert.Equal(3, await CountInAsync(acme, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(12, await CountInAsync(acme, "SELECT MAX(id) FROM aggregate_records"));
        Assert.Equal(13, await NextIdAsync("aggregate_records"));
    }

    /// <summary>
    /// Ids repeat between files only after a sequence fell behind, but a move
    /// that meets one must keep both rows rather than drop the one arriving.
    /// </summary>
    [Fact]
    public async Task AMoveKeepsEveryRowEvenWhenAnIdIsAlreadyTaken()
    {
        await OlderDatabaseAsync();
        await UpgradeAsync();

        // Beta's file holding an id 10 of its own, as Acme's does.
        await using (var beta = new SqliteConnection($"Data Source={FileOf("c-other", "beta", "t-a")};Pooling=False"))
        {
            await beta.OpenAsync();
            await ExecuteAsync(beta, $"""
                INSERT INTO aggregate_records
                  (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
                  VALUES (10,'r-other','t-a','c-other','d-other','{When}','198.51.100.2',100,'pass');
                """);
        }

        Assert.Equal(ReportStore.AssignOutcome.Assigned,
            await new ReportStore(_dbPath, "orga").AssignDomainAsync("acme.com", "beta"));

        var path = FileOf("c-other", "beta", "t-a");
        Assert.Equal(4, await CountInAsync(path, "SELECT COUNT(*) FROM aggregate_records"));
        Assert.Equal(122, await CountInAsync(path, "SELECT SUM(message_count) FROM aggregate_records"));
        Assert.Equal(2, await CountInAsync(path, "SELECT COUNT(*) FROM aggregate_records WHERE domain_id = 'd-a'"));
        Assert.Equal(0, await CountInAsync(FileOf("c-a", "acme", "t-a"), "SELECT COUNT(*) FROM aggregate_records"));

        // The one that met a taken id was numbered from the sequence every file
        // shares, past the largest anywhere - not by Beta's file alone, which
        // would have made it 13: an id the sequence may already have handed
        // to another client's row.
        Assert.Equal(41, await CountInAsync(path, "SELECT id FROM aggregate_records WHERE domain_id = 'd-a' AND message_count = 10"));
        Assert.Equal(42, await NextIdAsync("aggregate_records"));
    }
}
