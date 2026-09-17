using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// The one thing the web app is allowed to write: which client a domain
/// belongs to.
///
/// ReportStoreConnection exists because pages otherwise only read, so that a
/// page cannot accidentally modify a customer's data and a long query cannot
/// block an ingest run. That rule still holds for everything else, and this is
/// its single deliberate exception rather than a general loosening: onboarding
/// is the one operation an operator performs from a screen rather than from a
/// scheduled run, and leaving it CLI-only means a product whose first step
/// after importing a mailbox is to open a terminal.
///
/// It is scoped to exactly two operations, and neither touches report data.
/// Nothing here can alter a stored report, only the client a domain hangs off.
/// </summary>
public sealed class OnboardingService(DatabaseInfo database)
{
    private readonly ReportStore _store = new(database.Path);

    public Task<IReadOnlyList<ReportStore.ClientSummary>> GetClientsAsync(CancellationToken ct = default) =>
        _store.GetClientsAsync(ct);

    public Task<IReadOnlyList<string>> GetUnassignedDomainsAsync(CancellationToken ct = default) =>
        _store.GetUnassignedDomainsAsync(ct);

    /// <summary>Creates a client. Returns its slug, or null when the slug is taken.</summary>
    public Task<string?> CreateClientAsync(string name, string? slug = null, CancellationToken ct = default) =>
        _store.CreateClientAsync(name, slug, ct);

    /// <summary>Files a domain, and everything already stored for it, under a client.</summary>
    public Task<ReportStore.AssignOutcome> AssignAsync(string domain, string clientSlug, CancellationToken ct = default) =>
        _store.AssignDomainAsync(domain, clientSlug, ct);
}
