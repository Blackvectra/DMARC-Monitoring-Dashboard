namespace DmarcMonitor.Core.Remediation;

/// <summary>One record as a provider holds it.</summary>
/// <param name="Id">
/// The provider's own handle for it. Cloudflare gives every record one; Azure
/// addresses a whole record set, so there it is the set's path and the value
/// tells the entries apart.
/// </param>
public sealed record DnsProviderRecord(string Name, string Type, string Value, int Ttl, string Id);

/// <summary>
/// One write: publish Value at Name, replacing what is named or adding beside
/// what is there.
/// </summary>
/// <remarks>
/// Both ways of naming what is replaced are carried because providers differ.
/// Cloudflare replaces by record id; Azure keeps every TXT value at a name in
/// one set and has no id per value, so it replaces by matching the old value.
/// With neither set the value is added alongside whatever else is there, and
/// what else is there matters: an apex holds verification tokens for half a
/// dozen services, and a write that replaced the set would delete them all.
/// </remarks>
public sealed record DnsRecordWrite(
    string Name,
    string Type,
    string Value,
    string? ReplacesId = null,
    string? ReplacesValue = null,
    int Ttl = 300);

/// <summary>What a provider said about a write. Accepted is not the same as visible.</summary>
public sealed record ProviderWrite(bool Success, string Id, string Error)
{
    public static ProviderWrite Ok(string id) => new(true, id, "");
    public static ProviderWrite Failed(string error) => new(false, "", error);
}

/// <summary>
/// Somewhere DNS records can be read from and written to.
///
/// Small on purpose. Everything the product does to a zone is read a name,
/// replace one value at it, or remove one value from it; the guardrails
/// (snapshot first, verify after, roll back from the snapshot) live above this
/// so every provider gets them without reimplementing them.
/// </summary>
public interface IDnsProvider
{
    /// <summary>A short name for the audit trail: cloudflare, azuredns, manual.</summary>
    string Name { get; }

    /// <summary>
    /// Whether this provider can write at all.
    /// </summary>
    /// <remarks>
    /// False for the manual provider, whose job is to say what to publish
    /// when a zone has no API this can reach. A write attempted against it
    /// fails rather than pretending, so nothing is recorded as done that was
    /// only asked for.
    /// </remarks>
    bool CanWrite { get; }

    Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default);

    Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default);

    Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default);
}
