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
    private static string FindSchemaFile()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "db", "schema.sql");
            if (File.Exists(candidate)) { return candidate; }
        }
        throw new FileNotFoundException("Could not find db/schema.sql from the test output directory.");
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
    public async Task BuildsAWorkingDatabaseOnItsOwn()
    {
        // The case that matters: a machine with no checkout. If the resource
        // were truncated or half-embedded this still reads as "present".
        var path = Path.Combine(Path.GetTempPath(), $"dmarc-schema-{Guid.NewGuid():N}.db");
        try
        {
            var store = new ReportStore(path);
            await store.InitialiseAsync(DatabaseSchema.Sql);

            Assert.True(await store.IsInitialisedAsync());

            // And it is the whole schema, not just the tables IsInitialised
            // happens to look for.
            await using var connection = new SqliteConnection(
                new SqliteConnectionStringBuilder { DataSource = path }.ToString());
            await connection.OpenAsync();

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'";
            var tables = Convert.ToInt32(await command.ExecuteScalarAsync(), provider: null);

            Assert.True(tables >= 25, $"only {tables} tables were created");
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
