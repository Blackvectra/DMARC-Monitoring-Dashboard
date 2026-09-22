using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Writes the stored records out for something else to query.
///
/// The screens here are opinionated on purpose, and that is also their limit:
/// "every address that hit these three domains, aligned on SPF only, in a
/// six-hour window" is a question no fixed view answers and that nobody should
/// have to change code to ask. Rather than grow a query language, this hands
/// the rows over in a shape every other tool already reads - jq, a spreadsheet,
/// OpenSearch, Splunk - and lets those be the query language.
///
/// It is also the way to run both. Keep the retention window here short enough
/// that one SQLite file stays quick, ship the rows to an index, and let that
/// hold the long tail. --after-id makes that incremental rather than a full
/// re-export every night.
///
/// Writes to stdout unless --out, so it pipes. Every message it prints about
/// itself goes to stderr for the same reason.
/// </summary>
public static class ExportCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--org", "--client", "--domain", "--days",
                        "--format", "--out", "--after-id", "!--failures-only")
            is var bad and not 0)
        {
            return bad;
        }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}. This exports what is "
                                  + "stored, so it needs one.");
            return 66;
        }

        var format = (Args.Value(args, "--format") ?? "ndjson").Trim().ToLowerInvariant();
        if (format is not ("ndjson" or "json" or "csv"))
        {
            Console.Error.WriteLine($"Unknown format: {format}. Use ndjson (the default) or csv.");
            return 64;
        }

        if (Args.Value(args, "--after-id") is { } given && !long.TryParse(given, out _))
        {
            Console.Error.WriteLine($"--after-id wants the number a previous run printed, not '{given}'.");
            return 64;
        }

        var query = new ExportQuery
        {
            OrgSlug = Args.Value(args, "--org"),
            ClientSlug = Args.Value(args, "--client"),
            Domain = Args.Value(args, "--domain"),
            Days = Args.Value(args, "--days") is not null ? Args.Int(args, "--days", 30) : null,
            FailuresOnly = Args.Flag(args, "--failures-only"),
            AfterId = long.TryParse(Args.Value(args, "--after-id"), out var after) ? after : null,
        };

        var outPath = Args.Value(args, "--out");
        var exporter = new ReportExporter(dbPath);

        // The writer is built here rather than inside the exporter so that
        // stdout is never closed: this is meant to be the left-hand side of a
        // pipe, and closing somebody else's stdout only shows up there.
        TextWriter writer = outPath is null ? Console.Out : OwnerOnly(outPath);

        ExportResult result;
        try
        {
            result = await exporter
                .WriteAsync(query, writer, format == "csv" ? ExportFormat.Csv : ExportFormat.Ndjson, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            if (outPath is not null) { await writer.DisposeAsync().ConfigureAwait(false); }
        }

        if (result.Rows == 0)
        {
            Console.Error.WriteLine("Nothing matched. Widen the window with --days, or check the names.");
            return 0;
        }

        Console.Error.WriteLine($"{result.Rows:N0} record(s)"
                              + (outPath is null ? "" : $" to {Path.GetFullPath(outPath)}")
                              + $". Next run: --after-id {result.LastId}");

        return 0;
    }

    /// <summary>
    /// Opens the output file readable by its owner and nobody else.
    /// </summary>
    /// <remarks>
    /// An export is a complete dump of other people's mail data - every
    /// sending address, every domain, every authentication result, across
    /// whichever clients the query matched. Written with the ordinary umask it
    /// lands 0644, readable by any local account on the machine, which is a
    /// weaker setting than the database it was read from (0600).
    ///
    /// UnixCreateMode rather than a chmod afterwards, so there is never a
    /// moment where the file exists with the wrong permissions and rows are
    /// already going into it. Windows has no mode and inherits the directory's
    /// ACL, so it takes the plain path.
    /// </remarks>
    private static StreamWriter OwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows()) { return new StreamWriter(path); }

        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;   // 0600

        // UnixCreateMode applies only when the file is CREATED. Exporting over
        // one that already exists - the second run of the same command - kept
        // whatever mode it had, so a file that started life 0644 stayed
        // world-readable while this code claimed otherwise.
        var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            UnixCreateMode = ownerOnly,
        });

        try { File.SetUnixFileMode(path, ownerOnly); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left as it was. The export still runs; a file somebody else owns
            // is their permissions to set.
        }

        return new StreamWriter(stream);
    }
}
