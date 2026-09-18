using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Azure DNS, through the management API.
///
/// Azure keeps every TXT value at a name in one record set with no id per
/// value, so replacing one value means reading the set, swapping that entry
/// and writing the set back. Writing back only the new value would delete
/// every other TXT record at the apex, which is where the verification
/// tokens for every service the customer uses live.
/// </summary>
public sealed class AzureDnsProvider : IDnsProvider
{
    public const string ApiVersion = "2018-05-01";
    private const string Scope = "https://management.azure.com/.default";

    private readonly HttpClient _http;
    private readonly TokenCredential _credential;
    private readonly string _zone;
    private readonly string _base;

    public AzureDnsProvider(HttpClient http, TokenCredential credential, string subscriptionId, string resourceGroup, string zoneName)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentException.ThrowIfNullOrWhiteSpace(subscriptionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceGroup);
        ArgumentException.ThrowIfNullOrWhiteSpace(zoneName);

        _http = http;
        _credential = credential;
        _zone = zoneName.Trim().TrimEnd('.').ToLowerInvariant();
        _http.BaseAddress ??= new Uri("https://management.azure.com/");
        _base = $"subscriptions/{subscriptionId.Trim()}/resourceGroups/{resourceGroup.Trim()}/providers/Microsoft.Network/dnsZones/{_zone}";
    }

    public string Name => "azuredns";
    public bool CanWrite => true;

    public async Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var set = await GetSetAsync(name, type, ct).ConfigureAwait(false);
        if (set is null) { return []; }

        var id = SetPath(name, type);
        var (ttl, values, _) = set.Value;
        return [.. values.Select(v => new DnsProviderRecord(name, type.ToUpperInvariant(), v, ttl, id))];
    }

    public async Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(write);

        if (!string.Equals(write.Type, "TXT", StringComparison.OrdinalIgnoreCase))
        {
            return ProviderWrite.Failed($"Only TXT records are written here, not {write.Type}.");
        }

        try
        {
            var set = await GetSetAsync(write.Name, write.Type, ct).ConfigureAwait(false);
            var values = set is { } s ? s.Values.ToList() : [];
            var ttl = set is { } t ? t.Ttl : write.Ttl;

            if (write.ReplacesValue is not null)
            {
                var at = values.FindIndex(v => string.Equals(v, write.ReplacesValue, StringComparison.Ordinal));
                if (at < 0)
                {
                    return ProviderWrite.Failed($"No value equal to the one being replaced exists at {write.Name}. The zone changed since it was read.");
                }
                values[at] = write.Value;
            }
            else
            {
                values.Add(write.Value);
            }

            return await PutSetAsync(write.Name, write.Type, values, ttl, set?.ETag, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return ProviderWrite.Failed($"Could not reach Azure: {ex.Message}");
        }
    }

    public async Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        try
        {
            var set = await GetSetAsync(record.Name, record.Type, ct).ConfigureAwait(false);
            if (set is null) { return ProviderWrite.Failed($"Nothing is published at {record.Name}."); }

            var (ttl, values, etag) = set.Value;
            if (!values.Remove(record.Value)) { return ProviderWrite.Failed($"No such value at {record.Name}."); }

            if (values.Count > 0)
            {
                return await PutSetAsync(record.Name, record.Type, values, ttl, etag, ct).ConfigureAwait(false);
            }

            using var request = await Authed(HttpMethod.Delete, SetPath(record.Name, record.Type), ct).ConfigureAwait(false);
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            return response.IsSuccessStatusCode
                ? ProviderWrite.Ok(SetPath(record.Name, record.Type))
                : ProviderWrite.Failed($"Azure refused the delete: HTTP {(int)response.StatusCode} {await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)}");
        }
        catch (HttpRequestException ex)
        {
            return ProviderWrite.Failed($"Could not reach Azure: {ex.Message}");
        }
    }

    /// <summary>
    /// A record's name relative to the zone, which is how Azure addresses it.
    /// </summary>
    internal static string Relative(string name, string zone)
    {
        var n = name.Trim().TrimEnd('.').ToLowerInvariant();
        var z = zone.Trim().TrimEnd('.').ToLowerInvariant();

        if (n == z) { return "@"; }
        if (n.EndsWith("." + z, StringComparison.Ordinal)) { return n[..^(z.Length + 1)]; }

        throw new ArgumentException($"{name} is not inside the zone {zone}.", nameof(name));
    }

    /// <summary>
    /// Splits a value into the 255-character strings a TXT record is made of.
    /// </summary>
    /// <remarks>
    /// Azure requires each string in a value to fit, and a long SPF record
    /// does not. Resolvers join the strings back with nothing between them,
    /// which is what every reader here does too.
    /// </remarks>
    internal static List<string> Chunk(string value)
    {
        var chunks = new List<string>();
        for (var i = 0; i < value.Length; i += 255)
        {
            chunks.Add(value.Substring(i, Math.Min(255, value.Length - i)));
        }
        return chunks.Count == 0 ? [""] : chunks;
    }

    private string SetPath(string name, string type) =>
        $"{_base}/{type.ToUpperInvariant()}/{Relative(name, _zone)}?api-version={ApiVersion}";

    private async Task<(int Ttl, List<string> Values, string? ETag)?> GetSetAsync(string name, string type, CancellationToken ct)
    {
        using var request = await Authed(HttpMethod.Get, SetPath(name, type), ct).ConfigureAwait(false);
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound) { return null; }
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Azure refused the read: HTTP {(int)response.StatusCode} {await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)}");
        }

        var set = await response.Content.ReadFromJsonAsync<RecordSet>(Json, ct).ConfigureAwait(false);
        var values = set?.Properties?.TxtRecords?.Select(r => string.Concat(r.Value ?? [])).ToList() ?? [];
        return (set?.Properties?.Ttl ?? 300, values, set?.ETag);
    }

    /// <summary>
    /// Writes the set back, refusing if anyone else changed it first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Azure keeps every TXT value at a name in one record set, so changing
    /// one value means reading the set, swapping an entry and writing all of
    /// them back. Without a condition on the write that is a lost update with
    /// consequences: a verification token added by somebody else between the
    /// read and the write is not overwritten, it is deleted, and the service
    /// that issued it stops trusting the domain. Nothing in the response says
    /// so, because as far as Azure is concerned the write succeeded.
    /// </para>
    /// <para>
    /// <c>If-Match</c> on the etag read a moment ago makes Azure refuse
    /// instead. <c>If-None-Match: *</c> does the same job when there was no
    /// set at all, so a set created concurrently is not silently replaced by
    /// one holding only this record.
    /// </para>
    /// <para>
    /// Cloudflare needs none of this: it gives every value its own id, so a
    /// write there touches one record and cannot take its neighbours with it.
    /// </para>
    /// </remarks>
    private async Task<ProviderWrite> PutSetAsync(
        string name, string type, List<string> values, int ttl, string? etag, CancellationToken ct)
    {
        var body = new RecordSet
        {
            Properties = new Properties
            {
                Ttl = ttl,
                TxtRecords = [.. values.Select(v => new TxtEntry { Value = Chunk(v) })],
            },
        };

        using var request = await Authed(HttpMethod.Put, SetPath(name, type), ct).ConfigureAwait(false);
        request.Content = JsonContent.Create(body, options: Json);

        if (!string.IsNullOrWhiteSpace(etag))
        {
            request.Headers.TryAddWithoutValidation("If-Match", etag);
        }
        else
        {
            request.Headers.TryAddWithoutValidation("If-None-Match", "*");
        }

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

        // Said as what happened rather than as an HTTP code. A 412 here is not
        // a fault to retry blindly: the set is not what it was, so the values
        // being written back are no longer the right ones.
        if (response.StatusCode == HttpStatusCode.PreconditionFailed)
        {
            return ProviderWrite.Failed(
                $"The records at {name} changed while this was being written, so nothing was changed. "
                + "Read them again and plan from what is there now.");
        }

        return response.IsSuccessStatusCode
            ? ProviderWrite.Ok(SetPath(name, type))
            : ProviderWrite.Failed($"Azure refused the write: HTTP {(int)response.StatusCode} {await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)}");
    }

    private async Task<HttpRequestMessage> Authed(HttpMethod method, string uri, CancellationToken ct)
    {
        var token = await _credential.GetTokenAsync(new TokenRequestContext([Scope]), ct).ConfigureAwait(false);
        return new HttpRequestMessage(method, uri)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token.Token) },
        };
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class RecordSet
    {
        [JsonPropertyName("properties")] public Properties? Properties { get; set; }

        /// <summary>What the set looked like when it was read, for If-Match.</summary>
        [JsonPropertyName("etag")] public string? ETag { get; set; }
    }

    private sealed class Properties
    {
        [JsonPropertyName("TTL")] public int Ttl { get; set; }
        [JsonPropertyName("TXTRecords")] public List<TxtEntry>? TxtRecords { get; set; }
    }

    private sealed class TxtEntry
    {
        [JsonPropertyName("value")] public List<string>? Value { get; set; }
    }
}
