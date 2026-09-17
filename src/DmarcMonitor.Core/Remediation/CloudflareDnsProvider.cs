using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Cloudflare, through the v4 API with a zone-scoped token.
///
/// The token must be an API token with Zone:DNS:Edit on the one zone, never
/// the Global API Key: the key is the whole account, and this process holds
/// the credential for as long as it runs. Cloudflare gives every record its
/// own id, so replacing is a PUT to that id and adding is a POST.
/// </summary>
public sealed class CloudflareDnsProvider : IDnsProvider
{
    public const string DefaultBaseUri = "https://api.cloudflare.com/client/v4/";

    private readonly HttpClient _http;
    private readonly string _zoneId;

    public CloudflareDnsProvider(HttpClient http, string zoneId, string apiToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrWhiteSpace(zoneId);
        ArgumentException.ThrowIfNullOrWhiteSpace(apiToken);

        _http = http;
        _zoneId = zoneId.Trim();
        _http.BaseAddress ??= new Uri(DefaultBaseUri);
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
    }

    public string Name => "cloudflare";
    public bool CanWrite => true;

    public async Task<IReadOnlyList<DnsProviderRecord>> GetRecordsAsync(string name, string type, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var uri = $"zones/{_zoneId}/dns_records?type={Uri.EscapeDataString(type.ToUpperInvariant())}&name={Uri.EscapeDataString(Fqdn(name))}";
        using var response = await _http.GetAsync(uri, ct).ConfigureAwait(false);
        var body = await Read(response, ct).ConfigureAwait(false);

        if (!body.Success)
        {
            throw new HttpRequestException($"Cloudflare refused the read: {body.ErrorText}");
        }

        return [.. (body.Result ?? []).Select(r =>
            new DnsProviderRecord(r.Name ?? name, r.Type ?? type, Unquote(r.Content ?? ""), r.Ttl, r.Id ?? ""))];
    }

    public async Task<ProviderWrite> SetRecordAsync(DnsRecordWrite write, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(write);

        // Cloudflare's own idea of the id is the only one that counts. A
        // caller that knows only the old value gets it resolved here, so the
        // two providers can be driven the same way.
        var id = write.ReplacesId;
        if (id is null && write.ReplacesValue is not null)
        {
            var existing = await GetRecordsAsync(write.Name, write.Type, ct).ConfigureAwait(false);
            id = existing.FirstOrDefault(r => string.Equals(r.Value, write.ReplacesValue, StringComparison.Ordinal))?.Id;
            if (id is null)
            {
                return ProviderWrite.Failed($"No record equal to the one being replaced exists at {write.Name}. The zone changed since it was read.");
            }
        }

        var payload = new RecordBody { Type = write.Type.ToUpperInvariant(), Name = Fqdn(write.Name), Content = write.Value, Ttl = write.Ttl };

        try
        {
            using var response = id is null
                ? await _http.PostAsJsonAsync($"zones/{_zoneId}/dns_records", payload, Json, ct).ConfigureAwait(false)
                : await _http.PutAsJsonAsync($"zones/{_zoneId}/dns_records/{id}", payload, Json, ct).ConfigureAwait(false);

            var body = await Read(response, ct).ConfigureAwait(false);
            return body.Success && body.Single is not null
                ? ProviderWrite.Ok(body.Single.Id ?? "")
                : ProviderWrite.Failed($"Cloudflare refused the write: {body.ErrorText}");
        }
        catch (HttpRequestException ex)
        {
            return ProviderWrite.Failed($"Could not reach Cloudflare: {ex.Message}");
        }
    }

    public async Task<ProviderWrite> RemoveRecordAsync(DnsProviderRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Id.Length == 0) { return ProviderWrite.Failed("The record has no Cloudflare id to delete by."); }

        try
        {
            using var response = await _http.DeleteAsync($"zones/{_zoneId}/dns_records/{record.Id}", ct).ConfigureAwait(false);
            var body = await Read(response, ct).ConfigureAwait(false);
            return body.Success ? ProviderWrite.Ok(record.Id) : ProviderWrite.Failed($"Cloudflare refused the delete: {body.ErrorText}");
        }
        catch (HttpRequestException ex)
        {
            return ProviderWrite.Failed($"Could not reach Cloudflare: {ex.Message}");
        }
    }

    /// <summary>
    /// Strips the quoting Cloudflare returns TXT content in.
    /// </summary>
    /// <remarks>
    /// The API hands back "v=spf1 ..." with the quotes, and a long value as
    /// several quoted strings side by side. Stored and compared without them,
    /// or the snapshot never equals what the zone resolves to and every
    /// rollback target looks stale.
    /// </remarks>
    internal static string Unquote(string content)
    {
        var text = content.Trim();
        if (text.Length < 2 || text[0] != '"') { return text; }

        var result = new System.Text.StringBuilder(text.Length);
        var inside = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];

            if (inside && c == '\\' && i + 1 < text.Length)
            {
                result.Append(text[++i]);   // an escaped character, kept as itself
            }
            else if (c == '"')
            {
                inside = !inside;
            }
            else if (inside)
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    private static string Fqdn(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    private static async Task<Envelope> Read(HttpResponseMessage response, CancellationToken ct)
    {
        // Cloudflare says why in the body even on a 4xx, so the body is read
        // before the status is judged.
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Envelope? body = null;
        try
        {
            if (text.Length > 0) { body = JsonSerializer.Deserialize<Envelope>(text, Json); }
        }
        catch (JsonException)
        {
            // Fall through to the status-based answer below.
        }

        body ??= new Envelope { Success = false };
        if (!response.IsSuccessStatusCode && body.Errors.Count == 0)
        {
            body.Errors.Add(new ApiError { Message = $"HTTP {(int)response.StatusCode}" });
            body.Success = false;
        }

        return body;
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class Envelope
    {
        public bool Success { get; set; }
        public List<ApiError> Errors { get; set; } = [];

        // 'result' is a list on a query and an object on a single-record
        // write. JsonElement lets one envelope carry both.
        [JsonPropertyName("result")]
        public JsonElement ResultRaw { get; set; }

        [JsonIgnore]
        public List<RecordBody>? Result =>
            ResultRaw.ValueKind == JsonValueKind.Array ? ResultRaw.Deserialize<List<RecordBody>>(Json) : null;

        [JsonIgnore]
        public RecordBody? Single =>
            ResultRaw.ValueKind == JsonValueKind.Object ? ResultRaw.Deserialize<RecordBody>(Json) : null;

        [JsonIgnore]
        public string ErrorText => Errors.Count == 0 ? "no reason given" : string.Join("; ", Errors.Select(e => e.Message));
    }

    private sealed class ApiError
    {
        public int Code { get; set; }
        public string Message { get; set; } = "";
    }

    private sealed class RecordBody
    {
        public string? Id { get; set; }
        public string? Type { get; set; }
        public string? Name { get; set; }
        public string? Content { get; set; }
        public int Ttl { get; set; }
    }
}
