using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// The schema compiled into the binary.
///
/// A published binary creates databases from this copy rather than from
/// db/schema.sql, which is not shipped. Nothing at run time compares the two,
/// so without a test the embedded copy can quietly go missing or fall behind
/// the file, and the failure lands on the first machine somebody installs it
/// on rather than here.
/// </summary>
public sealed class DatabaseSchemaTests
{
    private static string FindSchemaFile(string name = "schema.sql")
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "db", name);
            if (File.Exists(candidate)) { return candidate; }
        }
        throw new FileNotFoundException($"Could not find db/{name} from the test output directory.");
    }

    [Fact]
    public void IsTheSameSchemaAsTheFileInTheRepository()
    {
        // Byte-for-byte apart from line endings, which git may rewrite on a
        // Windows checkout and which SQLite does not care about either way.
        var onDisk = File.ReadAllText(FindSchemaFile()).ReplaceLineEndings("\n");
        var embedded = DatabaseSchema.Sql.ReplaceLineEndings("\n");

        Assert.Equal(onDisk, embedded);
    }

    [Fact]
    public void TheClientSchemaIsTheSameAsItsFileToo()
    {
        var onDisk = File.ReadAllText(FindSchemaFile("client-schema.sql")).ReplaceLineEndings("\n");
        var embedded = DatabaseSchema.ClientSql.ReplaceLineEndings("\n");

        Assert.Equal(onDisk, embedded);
    }

    [Fact]
    public void EveryTableIsInExactlyOneOfTheTwoSchemas()
    {
        // The two files between them are what the single database was. A
        // table in both would be written to one and read from the other; a
        // table in neither was dropped by 0019 and never rebuilt.
        static HashSet<string> TablesOf(string sql)
        {
            using var db = new SqliteConnection("Data Source=:memory:;Pooling=False");
            db.Open();
            using (var create = db.CreateCommand()) { create.CommandText = sql; create.ExecuteNonQuery(); }
            using var list = db.CreateCommand();
            list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
            using var reader = list.ExecuteReader();
            var names = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read()) { names.Add(reader.GetString(0)); }
            return names;
        }

        var organization = TablesOf(DatabaseSchema.Sql);
        var client = TablesOf(DatabaseSchema.ClientSql);
        var single = TablesOf(File.ReadAllText(FindSchemaFile(Path.Combine("history", "0018-single-database.sql"))));

        // Bookkeeping every file has, and what only the split introduced.
        var own = new[] { "schema_migrations" };
        Assert.Empty(organization.Intersect(client).Except(own));

        var accounted = organization.Union(client).Except(["client_file", "row_ids"]).ToHashSet();
        Assert.Equal(single.OrderBy(t => t), accounted.OrderBy(t => t));
    }

    [Fact]
    public async Task BuildsAWorkingDatabaseOnItsOwn()
    {
        // The case that matters: a machine with no checkout. If the resource
        // were truncated or half-embedded this still reads as "present".
        var path = Path.Combine(Path.GetTempPath(), $"dmarc-schema-{Guid.NewGuid():N}.db");
        try
        {
            var store = new ReportStore(path);
            await store.InitializeAsync(DatabaseSchema.Sql);

            Assert.True(await store.IsInitializedAsync());

            // And it is the whole schema, not just the tables IsInitialized
            // happens to look for.
            await using var connection = new SqliteConnection(
                new SqliteConnectionStringBuilder { DataSource = path }.ToString());
            await connection.OpenAsync();

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'";
            var tables = Convert.ToInt32(await command.ExecuteScalarAsync(), provider: null);

            // The organization's fifteen; each client's reports are in a file
            // of its own, built from client-schema.sql.
            Assert.True(tables >= 15, $"only {tables} tables were created");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try { File.Delete(path + suffix); } catch (IOException) { }
            }
        }
    }
}
