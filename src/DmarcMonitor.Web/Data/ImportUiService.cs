using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// Runs a folder import on behalf of a page.
///
/// The second write path, and like OnboardingService a deliberate exception to
/// the read-only rule rather than a loosening of it: importing is the step
/// between exporting a mailbox and seeing anything at all, and requiring a
/// terminal for it makes the browser a viewer rather than the product.
///
/// It delegates to FolderImporter, which the CLI also uses, so the two cannot
/// disagree about what a folder contained.
/// </summary>
public sealed class ImportUiService(DatabaseInfo database)
{
    private readonly ReportStore _store = new(database.Path);

    public Task<ImportResult> ImportAsync(
        string folder, IProgress<int>? progress = null, CancellationToken ct = default) =>
        new FolderImporter(_store).ImportAsync(folder, progress, ct);

    public Task<IReadOnlyList<string>> GetUnassignedDomainsAsync(CancellationToken ct = default) =>
        _store.GetUnassignedDomainsAsync(ct);
}
