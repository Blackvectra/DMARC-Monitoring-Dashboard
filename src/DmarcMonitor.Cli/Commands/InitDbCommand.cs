using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>Creates the SQLite database from db/schema.sql.</summary>
public static class InitDbCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--schema") is var bad and not 0) { return bad; }

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
            if (await store.IsInitializedAsync(ct).ConfigureAwait(false))
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
            await store.InitializeAsync(schema, ct).ConfigureAwait(false);
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

    /// <summary>
    /// Complains about the first flag that is not one this command takes, and
    /// returns 64. Returns 0 when every flag is recognized.
    /// </summary>
    /// <remarks>
    /// Flags used to be looked up by name and anything else ignored, so a
    /// mistyped one did not fail - it silently changed what the command did.
    ///
    ///     dmarc report --client acme --moth 2026-09
    ///
    /// wrote last month's report instead, and the operator sent a customer the
    /// wrong month with nothing on screen to suggest it. Worse:
    ///
    ///     dmarc client add --name "Morton, ND" --slugg morton-nd
    ///
    /// filed the client as 'morton-com' rather than the slug asked for, and
    /// the slug is permanent because it goes into report filenames.
    ///
    /// A value that happens to begin with two dashes is not a flag here; only
    /// the positions a flag can occupy are checked, so "--reason --urgent" is
    /// still a reason.
    ///
    /// A flag given TWICE is refused too, which is a different mistake with
    /// the same shape. Value() returns the first match and drops the rest, so
    ///
    ///     dmarc import --from .\dmarc.exe import --from "C:\dmarc-export"
    ///
    /// - a command line pasted twice, which is an ordinary thing to do in a
    /// terminal - imported the executable itself, reported "files seen 1, not
    /// reports 1", and exited 0. Nothing on screen suggested the folder that
    /// was actually wanted had never been looked at. No command here takes a
    /// repeated flag, so there is no case where the second one is meant to be
    /// discarded silently.
    /// </remarks>
    public static int Reject(string[] args, params string[] known)
    {
        var takesValue = new HashSet<string>(known.Where(k => !k.StartsWith('!')),
                                             StringComparer.OrdinalIgnoreCase);
        var all = new HashSet<string>(known.Select(k => k.TrimStart('!')), StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal)) { continue; }

            if (all.Contains(arg))
            {
                if (!seen.Add(arg))
                {
                    Console.Error.WriteLine($"{arg} was given more than once.");
                    Console.Error.WriteLine("Only the first one would have been used, which is rarely what was meant.");
                    Console.Error.WriteLine("If a command line was pasted twice, run just one copy of it.");
                    Console.Error.WriteLine();
                    return 64;
                }

                // Step over this flag's value, so a value of its own that
                // looks like a flag is not then judged as one.
                if (takesValue.Contains(arg) && i + 1 < args.Length) { i++; }
                continue;
            }

            Console.Error.WriteLine($"Unknown option: {arg}");
            var closest = Closest(arg, all);
            if (closest is not null) { Console.Error.WriteLine($"Did you mean {closest}?"); }
            Console.Error.WriteLine();
            return 64;
        }

        return 0;
    }

    /// <summary>
    /// The known flag within one or two edits of what was typed, if any. Two
    /// covers the ordinary slips - a doubled letter, a dropped one, a
    /// transposition - without reaching for something unrelated.
    /// </summary>
    private static string? Closest(string typed, IEnumerable<string> known)
    {
        string? best = null;
        var bestDistance = int.MaxValue;

        foreach (var candidate in known)
        {
            var d = Distance(typed, candidate);
            if (d < bestDistance) { (best, bestDistance) = (candidate, d); }
        }

        return bestDistance <= 2 ? best : null;
    }

    private static int Distance(string a, string b)
    {
        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) { previous[j] = j; }

        for (var i = 1; i <= a.Length; i++)
        {
            current[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = char.ToLowerInvariant(a[i - 1]) == char.ToLowerInvariant(b[j - 1]) ? 0 : 1;
                current[j] = Math.Min(Math.Min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }
}
