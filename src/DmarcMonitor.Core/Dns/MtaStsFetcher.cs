using System.Net;
using System.Net.Sockets;
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

    /// <summary>The host a policy is served from.</summary>
    internal static string HostFor(string domain) =>
        $"mta-sts.{domain.Trim().TrimEnd('.').ToLowerInvariant()}";

    /// <summary>
    /// True when every address a name resolves to is inside this network.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Where this is pointed is not entirely the operator's choice. The host
    /// comes from a domain in the book, and a domain gets into the book by a
    /// report arriving for it - with a shared reporting address, the
    /// documented default, the domain is taken from the report itself, and
    /// that address is published in every client's DMARC record. So anybody
    /// can email a report, have a domain of their choosing appear, and point
    /// mta-sts.&lt;it&gt; at 127.0.0.1, 10.0.0.5 or a metadata address.
    /// </para>
    /// <para>
    /// Certificate validation already stopped anything being read back: an
    /// internal service holds no certificate for somebody else's hostname.
    /// What it did not stop was the connection being attempted, and which way
    /// it failed saying whether something was listening - a port scan of the
    /// inside of the network, driven by an email.
    /// </para>
    /// <para>
    /// Checked at resolution rather than at the socket. Behind an egress proxy
    /// - normal in the networks this runs in - the socket goes to the proxy
    /// and the proxy resolves the real name itself, so there is no destination
    /// address to inspect at connect time. Guarding that socket refuses every
    /// fetch on every proxied machine, which is exactly what the first attempt
    /// at this did: the proxy sits on 127.0.0.1 and was refused as an internal
    /// address. The cost of checking earlier is that a name re-resolved
    /// between here and the request is not caught, which is why the
    /// certificate check remains the control that matters.
    /// </para>
    /// <para>
    /// A name that does not resolve at all is not "inside": it is a policy
    /// host that does not exist, and the fetch reports that in its own words.
    /// </para>
    /// </remarks>
    private static async Task<bool> ResolvesOnlyInsideAsync(string host, CancellationToken ct)
    {
        try
        {
            return OnlyInside(await System.Net.Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false));
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>
    /// The decision itself, separated from the resolving so it can be tested
    /// without a network.
    /// </summary>
    /// <remarks>
    /// An empty list is not "inside". A name that resolves to nothing is a
    /// policy host that does not exist, which the fetch reports in its own
    /// words - and answering "inside this network" for it would be a sentence
    /// about something nobody established.
    ///
    /// One reachable address is enough. A host that answers publicly and also
    /// carries an internal address is an ordinary split-horizon arrangement,
    /// not an attack.
    /// </remarks>
    internal static bool OnlyInside(IReadOnlyList<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        return addresses.Count > 0 && addresses.All(IsInternal);
    }

    /// <summary>
    /// Whether an address belongs to this machine or the network around it.
    /// </summary>
    /// <remarks>
    /// Link-local covers the cloud metadata services at 169.254.169.254 and
    /// fd00:ec2::254, which are the addresses worth naming out loud even
    /// though the certificate check would already have refused them.
    /// </remarks>
    internal static bool IsInternal(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6) { address = address.MapToIPv4(); }

        if (IPAddress.IsLoopback(address)) { return true; }
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) { return true; }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // fe80::/10 link-local, fc00::/7 unique-local.
            return address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || (address.GetAddressBytes()[0] & 0xFE) == 0xFC;
        }

        var b = address.GetAddressBytes();

        return b[0] switch
        {
            10 => true,                                  // 10.0.0.0/8
            127 => true,                                 // loopback, caught above too
            169 when b[1] == 254 => true,                // 169.254.0.0/16, metadata
            172 when b[1] >= 16 && b[1] <= 31 => true,   // 172.16.0.0/12
            192 when b[1] == 168 => true,                // 192.168.0.0/16
            100 when b[1] >= 64 && b[1] <= 127 => true,  // 100.64.0.0/10 carrier NAT
            0 => true,
            _ => false,
        };
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
        var host = HostFor(domain);

        if (await ResolvesOnlyInsideAsync(host, ct).ConfigureAwait(false))
        {
            return ServedPolicy.Missing(
                $"{host} resolves only to addresses inside this network, which a policy host never does");
        }

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
