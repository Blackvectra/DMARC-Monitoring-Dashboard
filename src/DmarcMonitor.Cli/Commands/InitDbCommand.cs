using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>Creates the SQLite database from db/schema.sql.</summary>
public static class InitDbCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        // A named --schema is an explicit instruction and must not be silently
        // replaced by the built-in copy: somebody pointing at a file is
        // usually testing a change to it, and quietly using a different
        // schema would be the hardest kind of bug to see.
        var schemaPath = Args.Value(args, "--schema");
        if (schemaPath is not null && !File.Exists(schemaPath))
        {
            Console.Error.WriteLine($"No schema file at {schemaPath}.");
            return 66;
        }

        schemaPath ??= FindSchema();

        // Refuse rather than overwrite. Re-running the schema against a
        // populated database would fail partway through and leave it in an
        // unclear state, which is worse than declining up front.
        if (File.Exists(dbPath))
        {
            var store = new ReportStore(dbPath);
            if (await store.IsInitialisedAsync(ct).ConfigureAwait(false))
            {
                // Existing and ours: bring it up to date rather than declining.
                // This is the upgrade path, and running it is what stops a new
                // build meeting an old database and failing on a table that
                // was added after it was created.
                var result = await DatabaseMigrations.ApplyAsync(dbPath, ct).ConfigureAwait(false);

                if (result.Changed)
                {
                    Console.WriteLine($"{dbPath} was already a DMARC Monitor database. Brought it up to date:");
                    foreach (var applied in result.Applied) { Console.WriteLine($"  {applied}"); }
                }
                else
                {
                    Console.WriteLine($"{dbPath} already exists and is up to date (schema {result.Version}).");
                }

                return 0;
            }

            Console.Error.WriteLine($"{dbPath} exists but does not look like a DMARC Monitor database.");
            Console.Error.WriteLine("Move it aside, or choose another path with --db.");
            return 73;   // EX_CANTCREAT
        }

        // No file anywhere means this is a published binary rather than a
        // checkout, and the compiled-in copy is the right answer.
        var schema = schemaPath is null
            ? DatabaseSchema.Sql
            : await File.ReadAllTextAsync(schemaPath, ct).ConfigureAwait(false);

        try
        {
            var store = new ReportStore(dbPath);
            await store.InitialiseAsync(schema, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Could not create {dbPath}: {ex.Message}");

            // A half-built database is worse than none: the next run would
            // find some tables and assume the rest are there.
            TryDelete(dbPath);
            return 73;
        }

        Console.WriteLine($"Created {dbPath}");
        Console.WriteLine("Next: dmarc ingest --mailbox <address> --dry-run");
        return 0;
    }

    /// <summary>Looks for db/schema.sql beside the binary or up the tree, so the common case needs no flag.</summary>
    private static string? FindSchema()
    {
        var candidates = new List<string> { Path.Combine(AppContext.BaseDirectory, "schema.sql") };

        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        for (var i = 0; i < 6 && dir is not null; i++, dir = dir.Parent)
        {
            candidates.Add(Path.Combine(dir.FullName, "db", "schema.sql"));
        }

        return candidates.Find(File.Exists);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) { File.Delete(path); } }
        catch (IOException) { /* leave it; the message above already said what failed */ }
        catch (UnauthorizedAccessException) { }
    }
}

/// <summary>Minimal flag parsing, kept here so the commands stay readable.</summary>
internal static class Args
{
    public static string? Value(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }

    public static bool Flag(string[] args, string name) =>
        Array.Exists(args, a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

    public static int Int(string[] args, string name, int fallback) =>
        int.TryParse(Value(args, name), out var n) && n > 0 ? n : fallback;
}
