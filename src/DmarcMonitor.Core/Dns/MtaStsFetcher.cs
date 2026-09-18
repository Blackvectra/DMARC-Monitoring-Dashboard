using System.Net;
using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Dns;

/// <summary>
/// Fetches the policy file a domain is serving, the way a sender would.
///
/// Until this existed, the product could only tell you a domain's MTA-STS mode
/// if TLS reports happened to have arrived saying so - which meant it knew
/// nothing at all about a domain that had just been set up, or a prospect's.
/// A sender does not wait for reports; it fetches the file. So does this.
///
/// Everything about the request is what RFC 8461 §3.3 requires of a sender,
/// and the strictness is the point rather than pedantry:
///
///   HTTPS with a certificate that validates for mta-sts.&lt;domain&gt;. A policy
///   served over a certificate that does not validate is one an attacker
///   could have written, so senders ignore it - and so must this, or it
///   would report a domain as protected when no sender agrees.
///
///   No redirects followed. A policy that redirects elsewhere is not a policy
///   a sender will honour, and following one would let any domain claim
///   another's.
/// </summary>
public sealed class MtaStsFetcher(HttpClient? client = null)
{
    /// <summary>Largest policy file read. A real one is a few hundred bytes.</summary>
    public const int MaxBytes = 64 * 1024;

    private readonly HttpClient _http = client ?? Default();

    private static HttpClient Default()
    {
        var handler = new HttpClientHandler
        {
            // A sender does not follow these, so neither does this.
            AllowAutoRedirect = false,
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    public static string UrlFor(string domain) =>
        $"https://mta-sts.{domain.Trim().TrimEnd('.').ToLowerInvariant()}/.well-known/mta-sts.txt";

    /// <summary>
    /// What is being served for this domain, or why nothing usable is.
    /// </summary>
    /// <remarks>
    /// Never throws. Every failure is a sentence an operator can act on,
    /// because "the policy is not being served" is a finding rather than an
    /// error - it is the normal state of a domain nobody has set this up for.
    /// </remarks>
    public async Task<ServedPolicy> FetchAsync(string domain, string id = "", CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var url = UrlFor(domain);

        try
        {
            using var response = await _http.GetAsync(url, ct).ConfigureAwait(false);

            if ((int)response.StatusCode is >= 300 and < 400)
            {
                return ServedPolicy.Missing(
                    $"it redirects ({(int)response.StatusCode}), and a sender will not follow that");
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return ServedPolicy.Missing("there is no file there");
            }

            if (!response.IsSuccessStatusCode)
            {
                return ServedPolicy.Missing($"the server answered {(int)response.StatusCode}");
            }

            var text = await ReadBoundedAsync(response, ct).ConfigureAwait(false);
            if (text is null)
            {
                return ServedPolicy.Missing($"the file is larger than {MaxBytes / 1024} KB, so it is not a policy");
            }

            var policy = MtaStsPolicy.ParseFile(text, id);

            return policy is null
                ? new ServedPolicy(true, null, "the file does not parse as an MTA-STS policy")
                : new ServedPolicy(true, policy, null);
        }
        catch (HttpRequestException ex)
        {
            return ServedPolicy.Missing(Why(ex, domain));
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return ServedPolicy.Missing("it did not answer in time");
        }
    }

    /// <summary>
    /// Why the fetch failed, said in terms of the domain rather than the wire.
    /// </summary>
    /// <remarks>
    /// The three outcomes need three different fixes and arrive as one
    /// exception type. The message matters: "the proxy tunnel request failed
    /// with status 502" is true and tells an operator nothing, where "there is
    /// no host at mta-sts.acme.com" names the thing to create.
    /// </remarks>
    private static string Why(HttpRequestException ex, string domain)
    {
        var host = $"mta-sts.{domain.Trim().TrimEnd('.').ToLowerInvariant()}";

        for (Exception? inner = ex; inner is not null; inner = inner.InnerException)
        {
            if (inner is System.Security.Authentication.AuthenticationException)
            {
                return $"the certificate for {host} does not validate, so a sender would ignore the policy";
            }

            if (inner is System.Net.Sockets.SocketException socket)
            {
                return socket.SocketErrorCode is System.Net.Sockets.SocketError.HostNotFound
                                              or System.Net.Sockets.SocketError.NoData
                    ? $"there is no host at {host}"
                    : $"nothing answered at {host}";
            }
        }

        return $"nothing answered at {host}";
    }

    private static async Task<string?> ReadBoundedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > MaxBytes) { return null; }

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();

        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBytes) { return null; }
            buffer.Write(chunk, 0, read);
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }
}
