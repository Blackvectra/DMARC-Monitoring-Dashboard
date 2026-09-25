using System.Reflection;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Storage;

/// <summary>
/// SQL written for the single database, run against one split into client files.
/// </summary>
/// <remarks>
/// <para>
/// Tests seed their rows with SQL that names a tenant, its clients, their
/// domains and their reports in one script, as the single database let them.
/// Rather than route every statement to the file it belongs in, this does what
/// an upgrade does: the organization's database and every client's file are
/// gathered back into one database built from the schema as it was at 0018,
/// the SQL runs there, and migration 0019 splits the result again.
/// </para>
/// <para>
/// So every seed also runs the split, and what a test then reads is exactly
/// what an upgraded install would hold.
/// </para>
/// </remarks>
internal static class SingleDatabase
{
    /// <summary>db/history/0018-single-database.sql.</summary>
    public static string Schema { get; } = Load();

    /// <summary>
    /// Runs <paramref name="sql"/> as if the database at <paramref name="path"/>
    /// were still one file, then splits it into client files again.
    /// </summary>
    public static async Task ExecuteAsync(string path, string sql)
    {
        var files = new ClientDatabases(path);
        var merged = $"{path}.single-{Guid.NewGuid():N}.db";

        await using (var db = new SqliteConnection($"Data Source={merged};Pooling=False"))
        {
            await db.OpenAsync();
            await RunAsync(db, Schema);
            await RunAsync(db, "PRAGMA foreign_keys = OFF");

            if (File.Exists(path))
            {
                // The organization's tables, then every client file's rows.
                await CopyAsync(db, path, skip: ["schema_migrations", "row_ids"]);

                if (Directory.Exists(files.Folder))
                {
                    foreach (var file in Directory.EnumerateFiles(files.Folder, "*.db"))
                    {
                        await CopyAsync(db, file, skip: ["schema_migrations", "client_file"]);
                    }
                }
            }

            await RunAsync(db, "PRAGMA foreign_keys = ON");
            await RunAsync(db, sql);
        }

        SqliteConnection.ClearAllPools();
        DeleteSplit(path);
        File.Move(merged, path);

        await DatabaseMigrations.ApplyAsync(path);
        DeleteBackups(path);
    }

    /// <summary>One value, read as if the database were still one file.</summary>
    public static async Task<object?> ScalarAsync(string path, string sql)
    {
        await using var db = await new ClientDatabases(path).OpenAsync(ClientScope.Organization(null));
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }

    /// <summary>A count, read as if the database were still one file.</summary>
    public static async Task<long> CountAsync(string path, string sql) =>
        Convert.ToInt64(await ScalarAsync(path, sql) ?? 0L, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// A database a test made, with its journals, its client folder and any
    /// copy the split kept of it.
    /// </summary>
    public static void Delete(string path)
    {
        SqliteConnection.ClearAllPools();
        DeleteSplit(path);
        DeleteBackups(path);
    }

    private static void DeleteSplit(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            try { File.Delete(path + suffix); } catch (IOException) { }
        }

        var folder = ClientDatabases.FolderFor(path);
        try { if (Directory.Exists(folder)) { Directory.Delete(folder, recursive: true); } }
        catch (IOException) { }
    }

    private static void DeleteBackups(string path)
    {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full)!;
        var name = Path.GetFileNameWithoutExtension(full);

        foreach (var backup in Directory.EnumerateFiles(dir, $"{name}.pre-0019*"))
        {
            try { File.Delete(backup); } catch (IOException) { }
        }
    }

    /// <summary>Copies every table the source shares with the merged database, column by column.</summary>
    private static async Task CopyAsync(SqliteConnection db, string source, IReadOnlyCollection<string> skip)
    {
        await using (var attach = db.CreateCommand())
        {
            attach.CommandText = "ATTACH DATABASE $file AS src";
            attach.Parameters.AddWithValue("$file", source);
            await attach.ExecuteNonQueryAsync();
        }

        var tables = new List<string>();
        await using (var list = db.CreateCommand())
        {
            list.CommandText = """
                SELECT s.name FROM src.sqlite_master s
                WHERE s.type = 'table' AND s.name NOT LIKE 'sqlite_%'
                  AND EXISTS (SELECT 1 FROM main.sqlite_master m WHERE m.type = 'table' AND m.name = s.name)
                """;
            await using var reader = await list.ExecuteReaderAsync();
            while (await reader.ReadAsync()) { tables.Add(reader.GetString(0)); }
        }

        foreach (var table in tables.Where(t => !skip.Contains(t)))
        {
            var mine = await ColumnsAsync(db, "main", table);
            var theirs = await ColumnsAsync(db, "src", table);
            var shared = string.Join(", ", mine.Where(theirs.Contains));

            await RunAsync(db, $"INSERT INTO main.{table} ({shared}) SELECT {shared} FROM src.{table}");
        }

        await RunAsync(db, "DETACH DATABASE src");
    }

    private static async Task<List<string>> ColumnsAsync(SqliteConnection db, string schema, string table)
    {
        var columns = new List<string>();
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}', '{schema}') ORDER BY cid";
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) { columns.Add(reader.GetString(0)); }
        return columns;
    }

    private static async Task RunAsync(SqliteConnection db, string sql)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static string Load()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("single-database.sql")
            ?? throw new InvalidOperationException("db/history/0018-single-database.sql is not embedded in the tests.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
