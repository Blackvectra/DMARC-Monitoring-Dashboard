using System.Runtime.CompilerServices;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Components.Forms;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// Runs an import on behalf of a page, from a folder or from dropped files.
///
/// The second write path, and like OnboardingService a deliberate exception to
/// the read-only rule rather than a loosening of it: importing is the step
/// between having reports and seeing anything at all, and requiring a terminal
/// for it makes the browser a viewer rather than the product.
///
/// It delegates to ReportImporter, which the CLI also uses, so the two cannot
/// disagree about what a file contained.
/// </summary>
public sealed class ImportUiService(DatabaseInfo database)
{
    private readonly string _path = database.Path;

    /// <summary>
    /// A store that files domains nobody has seen before under the given
    /// organization. Domains already known keep their own.
    /// </summary>
    private ReportStore Store(string organization) => new(_path, organization);

    /// <summary>
    /// Largest single file accepted from a browser.
    /// </summary>
    /// <remarks>
    /// Blazor requires this to be stated rather than defaulted, and the
    /// default is 512 KB, which rejects every mailbox export there is. A
    /// hundred megabytes is far more than the real export this was built
    /// against and still a number, because the file is read into memory
    /// before it is unpacked.
    /// </remarks>
    public const long MaxFileBytes = 100L * 1024 * 1024;

    /// <summary>Files accepted in one drop. Dropping a folder of thousands is normal.</summary>
    public const int MaxFiles = 5_000;

    /// <param name="organization">The organization new domains are filed under, by slug.</param>
    public Task<ImportResult> ImportAsync(
        string folder, string organization, IProgress<int>? progress = null, CancellationToken ct = default) =>
        new ReportImporter(Store(organization)).ImportFolderAsync(folder, progress, ct);

    /// <summary>
    /// Imports files dropped or chosen in the browser.
    /// </summary>
    /// <remarks>
    /// Streamed one at a time rather than read up front: a drop can be a
    /// thousand files, and pulling them all into memory before storing any of
    /// them would be the one way to make this fall over on the exports it
    /// exists for.
    /// </remarks>
    public Task<ImportResult> ImportUploadsAsync(
        IReadOnlyList<IBrowserFile> files, string organization, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        return new ReportImporter(Store(organization)).ImportAsync(ReadAsync(files, ct), progress, ct);
    }

    public Task<IReadOnlyList<string>> GetUnassignedDomainsAsync(string? tenantId, CancellationToken ct = default) =>
        Store(ReportStore.DefaultTenantSlug).GetUnassignedDomainsAsync(tenantId, ct);

    private static async IAsyncEnumerable<ImportFile> ReadAsync(
        IReadOnlyList<IBrowserFile> files, [EnumeratorCancellation] CancellationToken ct)
    {
        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) { yield break; }

            // One file failing to arrive is reported and the rest continue.
            // A dropped batch that stops dead on the first oversized file is
            // how somebody loses the other nine hundred.
            yield return await ReadOneAsync(file, ct).ConfigureAwait(false);
        }
    }

    private static async Task<ImportFile> ReadOneAsync(IBrowserFile file, CancellationToken ct)
    {
        try
        {
            using var buffer = new MemoryStream();
            await using var stream = file.OpenReadStream(MaxFileBytes, ct);
            await stream.CopyToAsync(buffer, ct).ConfigureAwait(false);

            return new ImportFile(file.Name, buffer.ToArray());
        }
        catch (IOException)
        {
            // Blazor throws this for a file over the limit, with a message
            // written for a developer. What an operator needs is the number
            // and what to do instead.
            return new ImportFile(file.Name, [],
                $"larger than the {MaxFileBytes / (1024 * 1024)} MB limit for an upload. "
                + "Unpack it and drop the files, or put it on the server and import the folder.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ImportFile(file.Name, [], ex.Message);
        }
    }
}
