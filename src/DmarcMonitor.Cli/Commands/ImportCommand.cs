using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Imports report files from a folder, without a mailbox.
///
/// Exists because the mailbox path needs a tenant and a certificate, and there
/// are plenty of reasons to load reports without either: proving the storage
/// and the screens work, importing an archive somebody exported, or answering
/// "what does this pile of files actually say" for a prospect.
/// </summary>
public static class ImportCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var folder = Args.Value(args, "--from");

        if (string.IsNullOrWhiteSpace(folder))
        {
            Console.Error.WriteLine("Give me a folder: dmarc import --from <folder> [--db <path>]");
            return 64;
        }

        if (!Directory.Exists(folder))
        {
            Console.Error.WriteLine($"No such folder: {folder}");
            return 66;
        }

        var store = new ReportStore(dbPath);
        if (!await store.IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        var files = Directory
            .EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        int stored = 0, duplicates = 0, skipped = 0, failed = 0;
        var seen = 0;

        // A folder exported from a real mailbox is hundreds of files, and a run
        // that prints nothing until it finishes is indistinguishable from one
        // that has hung. Every hundred is often enough to show movement without
        // burying the errors, which are the lines actually worth reading.
        const int ProgressEvery = 100;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            seen++;
            if (seen % ProgressEvery == 0)
            {
                Console.WriteLine($"  {seen} of {files.Count} read, {stored} stored");
            }

            byte[] bytes;
            try { bytes = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false); }
            catch (IOException ex) { Console.Error.WriteLine($"  {Path.GetFileName(file)}: {ex.Message}"); failed++; continue; }

            var extracted = ReportAttachment.Extract(Path.GetFileName(file), bytes);
            if (extracted.Count == 0) { skipped++; continue; }

            foreach (var report in extracted)
            {
                try
                {
                    string? id = null;

                    if (report.Kind == ReportKind.DmarcAggregate)
                    {
                        var parsed = AggregateReportParser.Parse(report.Content);
                        if (!parsed.Success) { Console.Error.WriteLine($"  {report.FileName}: {parsed.Error}"); failed++; continue; }
                        id = await store.SaveAggregateAsync(parsed.Report!, report.Content, null, ct).ConfigureAwait(false);
                    }
                    else if (report.Kind == ReportKind.TlsRpt)
                    {
                        var parsed = TlsReportParser.Parse(report.Content);
                        if (!parsed.Success) { Console.Error.WriteLine($"  {report.FileName}: {parsed.Error}"); failed++; continue; }
                        id = await store.SaveTlsAsync(parsed.Report!, report.Content, null, ct).ConfigureAwait(false);
                    }

                    // A null id means the database refused it as a duplicate,
                    // which is the expected outcome of importing a folder twice
                    // and is not an error.
                    if (id is not null) { stored++; } else { duplicates++; }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Console.Error.WriteLine($"  {report.FileName}: {ex.Message}");
                    failed++;
                }
            }
        }

        Console.WriteLine($"  files seen      {files.Count}");
        Console.WriteLine($"  reports stored  {stored}");
        if (duplicates > 0) { Console.WriteLine($"  already stored  {duplicates}"); }
        if (skipped > 0) { Console.WriteLine($"  not reports     {skipped}"); }
        if (failed > 0) { Console.WriteLine($"  failed          {failed}"); }

        var unassigned = await store.GetUnassignedDomainsAsync(ct).ConfigureAwait(false);
        if (unassigned.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"  {unassigned.Count} domain(s) not yet assigned to a client:");
            foreach (var d in unassigned) { Console.WriteLine($"    {d}"); }
        }

        return failed > 0 ? 1 : 0;
    }
}
