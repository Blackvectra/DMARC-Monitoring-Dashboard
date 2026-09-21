using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Imports report files from a folder or a single file, without a mailbox.
///
/// Exists because the mailbox path needs a tenant and a certificate, and there
/// are plenty of reasons to load reports without either: proving the storage
/// and the screens work, importing an archive somebody exported, or answering
/// "what does this pile of files actually say" for a prospect.
///
/// A file as well as a folder, because an export IS a file - one zip - and
/// pointing this at it was refused as "No such folder" for something that was
/// plainly there.
/// </summary>
public static class ImportCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--from", "--org") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var from = Args.Value(args, "--from");

        if (string.IsNullOrWhiteSpace(from))
        {
            Console.Error.WriteLine("Give me a folder or an export: dmarc import --from <folder or file> [--db <path>]");
            return 64;
        }

        var isFolder = Directory.Exists(from);
        if (!isFolder && !File.Exists(from))
        {
            Console.Error.WriteLine($"No such file or folder: {from}");
            return 66;
        }

        // Domains nobody has seen before go to this organisation; known ones
        // keep their own.
        var store = new ReportStore(dbPath, Args.Value(args, "--org") ?? ReportStore.DefaultTenantSlug);
        if (!await store.IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        // The same importer the browser uses. Two implementations of this
        // would drift, and "it worked from the terminal" is a support question
        // nobody can answer.
        var progress = new Progress<int>(n => Console.WriteLine($"  {n} file(s) read"));
        var importer = new ReportImporter(store);
        var result = isFolder
            ? await importer.ImportFolderAsync(from, progress, ct).ConfigureAwait(false)
            : await importer.ImportFileAsync(from, progress, ct).ConfigureAwait(false);

        foreach (var error in result.Errors) { Console.Error.WriteLine($"  {error}"); }

        Console.WriteLine($"  files seen      {result.FilesSeen}");
        Console.WriteLine($"  reports stored  {result.Stored}");
        if (result.AlreadyStored > 0) { Console.WriteLine($"  already stored  {result.AlreadyStored}"); }
        if (result.NotReports > 0) { Console.WriteLine($"  not reports     {result.NotReports}"); }
        if (result.Failed > 0) { Console.WriteLine($"  failed          {result.Failed}"); }
        if (result.StoppedEarly) { Console.WriteLine("  stopped early; run it again to carry on"); }

        var unassigned = await store.GetUnassignedDomainsAsync(ct: ct).ConfigureAwait(false);
        if (unassigned.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"  {unassigned.Count} domain(s) not yet assigned to a client:");
            foreach (var d in unassigned) { Console.WriteLine($"    {d}"); }
        }

        return result.Failed > 0 ? 1 : 0;
    }
}
