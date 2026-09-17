using DnsClient;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// The provider for a zone this cannot reach: reads what is live, writes nothing.
///
/// Exists so a domain whose registrar has no API still gets a plan, a
/// before-and-after, and an instruction to publish, and so that a write
/// against it fails loudly. Recording "applied" for a change somebody was only
/// asked to make would put it in a client report as work done.
/// </summary>
public sealed class ManualDnsProvider(ILookupClient? client = null) : IDnsProvider
{
    private readonly ILookupClient _client = client ?? new LookupClient(new LookupClientOptions
    {
        Timeout = TimeSpan.FromSeconds(5),
        Retries = 2,
        // The point of reading here is to see what is live right now, so a
        // cached answer from before somebody's edit is the wrong answer.
        UseCache = false,
    });

    public string Name => "manual";
    public bool CanWrite => false;

    public async Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var response = await _client.QueryAsync(name, QueryType.TXT, cancellationToken: ct).ConfigureAwait(false);

        return [.. response.Answers.TxtRecords()
            .Select(r => new DnsProviderRecord(name, "TXT", string.Concat(r.Text), (int)r.TimeToLive, "live"))];
    }

    public Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(write);
        return Task.FromResult(ProviderWrite.Failed(
            $"No DNS API is configured for this zone. Publish this yourself: {write.Type} {write.Name} = {write.Value}"));
    }

    public Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Task.FromResult(ProviderWrite.Failed(
            $"No DNS API is configured for this zone. Remove this yourself: {record.Type} {record.Name} = {record.Value}"));
    }
}
