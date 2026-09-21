using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// The one thing the web app is allowed to write: which client a domain
/// belongs to, and which organization that client belongs to.
///
/// ReportStoreConnection exists because pages otherwise only read, so that a
/// page cannot accidentally modify a customer's data and a long query cannot
/// block an ingest run. That rule still holds for everything else, and this is
/// its single deliberate exception rather than a general loosening: onboarding
/// is the one operation an operator performs from a screen rather than from a
/// scheduled run, and leaving it CLI-only means a product whose first step
/// after importing a mailbox is to open a terminal.
///
/// Everything here takes the caller's organization scope. A person who can
/// see one organization lists its clients, assigns its domains, and can do
/// nothing to anybody else's, because the scope is in the query rather than
/// in a check somebody could forget.
/// </summary>
public sealed class OnboardingService(DatabaseInfo database)
{
    private readonly ReportStore _store = new(database.Path);

    /// <param name="tenantId">One organization's, or null for every organization's.</param>
    public Task<IReadOnlyList<ReportStore.ClientSummary>> GetClientsAsync(string? tenantId, CancellationToken ct = default) =>
        _store.GetClientsAsync(tenantId, ct);

    public Task<IReadOnlyList<string>> GetUnassignedDomainsAsync(string? tenantId, CancellationToken ct = default) =>
        _store.GetUnassignedDomainsAsync(tenantId, ct);

    /// <summary>Every domain in scope, with the client it is filed under.</summary>
    public Task<IReadOnlyList<ReportStore.DomainSummary>> GetDomainsAsync(string? tenantId, CancellationToken ct = default) =>
        _store.GetDomainsAsync(tenantId, ct);

    /// <summary>Creates a client in an organization. Returns its slug, or null when the slug is taken.</summary>
    public Task<string?> CreateClientAsync(string name, string organization, CancellationToken ct = default) =>
        _store.CreateClientAsync(name, null, organization, ct);

    /// <summary>
    /// Files a domain, and everything already stored for it, under a client.
    /// The domain has to be in the caller's scope; the client may be in any
    /// organization the caller can see, which is how a domain moves between
    /// them.
    /// </summary>
    public Task<ReportStore.AssignOutcome> AssignAsync(
        string domain, string clientSlug, string? tenantId, CancellationToken ct = default) =>
        _store.AssignDomainAsync(domain, clientSlug, tenantId, ct);

    /// <summary>The customer's own login group for a client. Null clears it.</summary>
    public Task<bool> SetClientGroupAsync(string clientSlug, string? entraGroupId, string? tenantId, CancellationToken ct = default) =>
        _store.SetClientGroupAsync(clientSlug, entraGroupId, tenantId, ct);
}
