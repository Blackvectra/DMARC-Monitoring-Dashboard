namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// A zone held in memory, with Azure's shape: every value at a name lives in
/// one set and is addressed by its value.
///
/// For tests, and for the apply path's own dry runs. It is in Core rather than
/// the test project because a provider that behaves exactly like the real
/// ones, minus the network, is the thing every guardrail is proven against.
/// </summary>
public sealed class InMemoryDnsProvider : IDnsProvider
{
    private readonly Dictionary<string, List<string>> _zone = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public string Name => "memory";
    public bool CanWrite => true;

    /// <summary>Every write and removal, in order, so a test can assert on what was touched.</summary>
    public List<string> Log { get; } = [];

    /// <summary>Seeds one value at a name, alongside anything already there.</summary>
    public InMemoryDnsProvider Add(string name, string type, string value)
    {
        lock (_lock)
        {
            Values(name, type).Add(value);
        }
        return this;
    }

    public IReadOnlyList<string> ValuesAt(string name, string type = "TXT")
    {
        lock (_lock)
        {
            return _zone.TryGetValue(Key(name, type), out var v) ? [.. v] : [];
        }
    }

    public Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default)
    {
        lock (_lock)
        {
            IReadOnlyList<DnsProviderRecord> result = _zone.TryGetValue(Key(name, type), out var values)
                ? [.. values.Select(v => new DnsProviderRecord(name, type, v, 300, Key(name, type)))]
                : [];
            return Task.FromResult(result);
        }
    }

    public Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(write);

        lock (_lock)
        {
            var values = Values(write.Name, write.Type);

            if (write.ReplacesValue is not null)
            {
                var at = values.FindIndex(v => string.Equals(v, write.ReplacesValue, StringComparison.Ordinal));
                if (at < 0)
                {
                    return Task.FromResult(ProviderWrite.Failed(
                        $"No value equal to the one being replaced exists at {write.Name}. The zone changed since it was read."));
                }
                values[at] = write.Value;
            }
            else
            {
                values.Add(write.Value);
            }

            Log.Add($"set {write.Type} {write.Name} = {write.Value}");
            return Task.FromResult(ProviderWrite.Ok(Key(write.Name, write.Type)));
        }
    }

    public Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_lock)
        {
            var values = Values(record.Name, record.Type);
            if (!values.Remove(record.Value))
            {
                return Task.FromResult(ProviderWrite.Failed($"No such value at {record.Name}."));
            }

            if (values.Count == 0) { _zone.Remove(Key(record.Name, record.Type)); }
            Log.Add($"remove {record.Type} {record.Name} = {record.Value}");
            return Task.FromResult(ProviderWrite.Ok(record.Id));
        }
    }

    private List<string> Values(string name, string type)
    {
        var key = Key(name, type);
        if (!_zone.TryGetValue(key, out var values))
        {
            values = [];
            _zone[key] = values;
        }
        return values;
    }

    private static string Key(string name, string type) =>
        $"{type.ToUpperInvariant()}:{name.Trim().TrimEnd('.').ToLowerInvariant()}";
}
