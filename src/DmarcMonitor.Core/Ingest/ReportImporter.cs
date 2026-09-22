using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Forensic;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Ingest;

/// <summary>What an import did.</summary>
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

/// <summary>One file handed to the importer, already in memory.</summary>
/// <remarks>
/// A name and its bytes, nothing else, so the importer does not know or care
/// whether it came off a disk or out of a browser. The name is only ever used
/// for display and for stripping a .gz suffix; what a file IS gets decided by
/// looking at what came out of it.
/// </remarks>
/// <param name="Error">
/// Set when the file could not be produced at all - a locked file on disk, an
/// upload that died mid-stream. Carried rather than thrown so one unreadable
/// file among thousands is counted and named instead of ending the run.
/// </param>
public sealed record ImportFile(string Name, byte[] Content, string? Error = null);

/// <summary>
/// Imports report files, from a folder on the server or from an upload.
///
/// One implementation for both, because the alternative was a second importer
/// for the browser, and two importers that drift apart is how "it worked from
/// the terminal" becomes a support question nobody can answer.
///
/// Files reaching here were chosen by an operator - a path they typed, or
/// files they dropped - so extraction gets the larger of the two budgets. The
/// mail path, where files arrive unbidden from strangers, keeps the tight one.
/// </summary>
public sealed class ReportImporter(ReportStore store)
{
    private readonly ReportStore _store = store;

    /// <summary>Enough detail to act on, without rendering a thousand lines of noise.</summary>
    public const int MaxErrorsKept = 25;

    /// <summary>Imports every file in a folder, including subfolders.</summary>
    public Task<ImportResult> ImportFolderAsync(
        string folder, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        return ImportAsync(ReadFolderAsync(folder, ct), progress, ct);
    }

    /// <summary>Imports one file: a single report, or an export holding thousands.</summary>
    /// <remarks>
    /// A mailbox export is one zip, and <c>dmarc import --from the-export.zip</c>
    /// is the first thing anybody types with one. It was refused with "No such
    /// folder" for a file that was plainly there, and the way round it - unzip
    /// it first - was not said. The browser already took the zip whole; the
    /// command line now does too, through the same importer.
    /// </remarks>
    public Task<ImportResult> ImportFileAsync(
        string path, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return ImportAsync(ReadOneAsync(path, ct), progress, ct);
    }

    /// <summary>
    /// Imports files handed over one at a time.
    /// </summary>
    /// <remarks>
    /// Takes an async sequence rather than a list so the caller can read each
    /// upload off the wire as this gets to it, instead of holding every
    /// dropped file in memory at once.
    /// </remarks>
    public async Task<ImportResult> ImportAsync(
        IAsyncEnumerable<ImportFile> files, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(files);

        int stored = 0, duplicates = 0, skipped = 0, failed = 0, seen = 0;
        var errors = new List<string>();
        var stoppedEarly = false;

        await foreach (var file in files.WithCancellation(ct).ConfigureAwait(false))
        {
            // Cancellation returns what was already done rather than throwing.
            // Everything stored so far is committed, and the duplicate check
            // means running it again resumes rather than starting over.
            if (ct.IsCancellationRequested) { stoppedEarly = true; break; }

            seen++;
            if (seen % 25 == 0) { progress?.Report(seen); }

            if (file.Error is not null)
            {
                failed++;
                Add(errors, $"{file.Name}: {file.Error}");
                continue;
            }

            var budget = ExtractionBudget.ForOperator();
            var found = 0;

            foreach (var report in ReportAttachment.ExtractAll(file.Name, file.Content, budget))
            {
                if (ct.IsCancellationRequested) { stoppedEarly = true; break; }
                found++;

                try
                {
                    // A null id means the database refused it as a duplicate,
                    // which is the expected outcome of importing the same
                    // thing twice and is not an error.
                    var id = await SaveAsync(report, ct).ConfigureAwait(false);
                    if (id is null) { duplicates++; } else { stored++; }
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

            if (found == 0) { skipped++; }

            // Said out loud rather than left as a short count. An export that
            // was quietly cut off half way through looks exactly like an
            // export that was fully imported, and the difference is a client
            // reported on with half their mail missing.
            if (budget.Exhausted)
            {
                failed++;
                Add(errors, $"{file.Name}: too large to read in full. {found:N0} report(s) were taken from it and "
                          + $"there may be more. Unpack it and import the folder instead.");
            }

            if (stoppedEarly) { break; }
        }

        progress?.Report(seen);

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

    /// <summary>Stores one extracted report. Null when it was already stored.</summary>
    private async Task<string?> SaveAsync(ExtractedReport report, CancellationToken ct)
    {
        switch (report.Kind)
        {
            case ReportKind.DmarcAggregate:
            {
                var parsed = AggregateReportParser.Parse(report.Content);
                if (!parsed.Success) { throw new InvalidDataException(parsed.Error); }
                return await _store.SaveAggregateAsync(parsed.Report!, report.Content, null, arrivedAt: null, ct).ConfigureAwait(false);
            }

            case ReportKind.TlsRpt:
            {
                var parsed = TlsReportParser.Parse(report.Content);
                if (!parsed.Success) { throw new InvalidDataException(parsed.Error); }
                return await _store.SaveTlsAsync(parsed.Report!, report.Content, null, arrivedAt: null, ct).ConfigureAwait(false);
            }

            case ReportKind.DmarcFailure:
            {
                var parsed = ForensicReportParser.Parse(report.Content);
                if (!parsed.Success) { throw new InvalidDataException(parsed.Error); }
                return await _store.SaveForensicAsync(parsed.Report!, report.Content, null, arrivedAt: null, ct).ConfigureAwait(false);
            }

            default:
                // Unreachable: extraction only yields reports it recognized.
                // Kept so a new ReportKind cannot be silently counted as
                // stored without anybody writing the code to store it.
                throw new InvalidDataException($"{report.Kind} reports are not stored yet");
        }
    }

    private static async IAsyncEnumerable<ImportFile> ReadFolderAsync(
        string folder, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var files = Directory
            .EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal);

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) { yield break; }

            // Reported, not skipped silently: a folder half of which could
            // not be read must not come back looking like a clean import.
            yield return await ReadAsync(file, ct).ConfigureAwait(false);
        }
    }

    private static async IAsyncEnumerable<ImportFile> ReadOneAsync(
        string path, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        yield return await ReadAsync(path, ct).ConfigureAwait(false);
    }

    private static async Task<ImportFile> ReadAsync(string path, CancellationToken ct)
    {
        var name = Path.GetFileName(path);
        try
        {
            return new ImportFile(name, await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ImportFile(name, [], ex.Message);
        }
    }

    private static void Add(List<string> errors, string message)
    {
        if (errors.Count < MaxErrorsKept) { errors.Add(message); }
    }
}
