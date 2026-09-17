using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Ingest;

/// <summary>What a folder import did.</summary>
public sealed record ImportResult
{
    public int FilesSeen { get; init; }
    public int Stored { get; init; }
    public int AlreadyStored { get; init; }
    public int NotReports { get; init; }
    public int Failed { get; init; }

    /// <summary>Why individual files failed, capped so one bad folder cannot fill a page.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>True when the run stopped early rather than finishing.</summary>
    public bool StoppedEarly { get; init; }
}

/// <summary>
/// Imports report files from a folder on disk.
///
/// Lifted out of the CLI command so the same code runs behind a button. The
/// alternative was a second implementation for the browser, and two importers
/// that drift apart is how "it worked from the terminal" becomes a support
/// question nobody can answer.
/// </summary>
public sealed class FolderImporter(ReportStore store)
{
    private readonly ReportStore _store = store;

    /// <summary>Enough detail to act on, without rendering a thousand lines of noise.</summary>
    public const int MaxErrorsKept = 25;

    public async Task<ImportResult> ImportAsync(
        string folder, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);

        var files = Directory
            .EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        int stored = 0, duplicates = 0, skipped = 0, failed = 0, seen = 0;
        var errors = new List<string>();
        var stoppedEarly = false;

        foreach (var file in files)
        {
            // Cancellation returns what was already done rather than throwing.
            // Everything stored so far is committed, and the duplicate check
            // means running it again resumes rather than starting over.
            if (ct.IsCancellationRequested) { stoppedEarly = true; break; }

            seen++;
            if (seen % 25 == 0) { progress?.Report(seen); }

            byte[] bytes;
            try
            {
                bytes = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                stoppedEarly = true;
                break;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed++;
                Add(errors, $"{Path.GetFileName(file)}: {ex.Message}");
                continue;
            }

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
                        if (!parsed.Success)
                        {
                            failed++;
                            Add(errors, $"{report.FileName}: {parsed.Error}");
                            continue;
                        }
                        id = await _store.SaveAggregateAsync(parsed.Report!, report.Content, null, ct).ConfigureAwait(false);
                    }
                    else if (report.Kind == ReportKind.TlsRpt)
                    {
                        var parsed = TlsReportParser.Parse(report.Content);
                        if (!parsed.Success)
                        {
                            failed++;
                            Add(errors, $"{report.FileName}: {parsed.Error}");
                            continue;
                        }
                        id = await _store.SaveTlsAsync(parsed.Report!, report.Content, null, ct).ConfigureAwait(false);
                    }

                    // A null id means the database refused it as a duplicate,
                    // which is the expected outcome of importing a folder
                    // twice and is not an error.
                    if (id is not null) { stored++; } else { duplicates++; }
                }
                catch (OperationCanceledException)
                {
                    stoppedEarly = true;
                    break;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    failed++;
                    Add(errors, $"{report.FileName}: {ex.Message}");
                }
            }

            if (stoppedEarly) { break; }
        }

        return new ImportResult
        {
            FilesSeen = seen,
            Stored = stored,
            AlreadyStored = duplicates,
            NotReports = skipped,
            Failed = failed,
            Errors = errors,
            StoppedEarly = stoppedEarly,
        };
    }

    private static void Add(List<string> errors, string message)
    {
        if (errors.Count < MaxErrorsKept) { errors.Add(message); }
    }
}
