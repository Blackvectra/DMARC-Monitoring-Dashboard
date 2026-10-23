using System.Net;

namespace DmarcMonitor.Core.Intelligence;

/// <summary>
/// Names an address from the range it sits in, for when reverse DNS has not
/// named it.
/// </summary>
/// <remarks>
/// <para>
/// A fallback for reading, not a second source of truth. <see cref="SourceCatalog"/>
/// names from the PTR because that moves when the vendor does; this list does
/// not, so it holds only ranges the vendors themselves publish for their mail
/// (and, for hosting, ranges registered to the network), and it is consulted
/// only when no name is known. Without it a domain card reads as thirty
/// <c>2a01:111:f403:…</c> addresses that are all Microsoft, until somebody
/// runs the name lookups.
/// </para>
/// <para>
/// Like the catalogue it decides nothing. Every verdict still comes from what
/// was signed; a ColoCrossing label says who owns the wire, not that the mail
/// was hostile.
/// </para>
/// </remarks>
public static class SourceRanges
{
    private sealed record Range(IPAddress Network, int Prefix, SourceIdentity Identity);

    private static readonly Range[] Known =
    [
        // Exchange Online Protection, as Microsoft publishes it for SPF.
        .. Ranges("Microsoft 365", SourceKind.MailProvider, "outlook.com",
            "40.92.0.0/15", "40.107.0.0/16", "52.100.0.0/14", "104.47.0.0/17",
            "2a01:111:f400::/48", "2a01:111:f403::/48"),

        // Google's outbound mail, from _spf.google.com.
        .. Ranges("Google", SourceKind.MailProvider, "google.com",
            "209.85.128.0/17", "74.125.0.0/16", "64.233.160.0/19", "66.102.0.0/20",
            "2607:f8b0:4000::/36", "2001:4860:4000::/36", "2a00:1450:4000::/36"),

        // KnowBe4's published simulation and training senders.
        .. Ranges("KnowBe4", SourceKind.Marketing, "knowbe4.com",
            "147.160.167.0/26", "23.21.109.197/32", "23.21.109.212/32"),

        .. Ranges("Mailchimp", SourceKind.Marketing, "mailchimp.com",
            "198.2.128.0/18", "205.201.128.0/20"),

        .. Ranges("SendGrid", SourceKind.Marketing, "sendgrid.net",
            "167.89.0.0/17", "168.245.0.0/17", "149.72.0.0/16"),

        .. Ranges("Amazon SES", SourceKind.Marketing, "amazonses.com",
            "54.240.0.0/18"),

        // AS36352. Hosting: who owns the wire, nothing more.
        .. Ranges("ColoCrossing", SourceKind.Hosting, "colocrossing.com",
            "107.172.0.0/14", "23.94.0.0/15", "192.3.0.0/16", "192.210.128.0/17"),
    ];

    /// <summary>What the range holding <paramref name="address"/> is, or null.</summary>
    public static SourceIdentity? Identify(string? address)
    {
        if (!IPAddress.TryParse(address?.Trim(), out var ip)) { return null; }
        if (ip.IsIPv4MappedToIPv6) { ip = ip.MapToIPv4(); }

        foreach (var range in Known)
        {
            if (Contains(range.Network, range.Prefix, ip)) { return range.Identity; }
        }

        return null;
    }

    private static IEnumerable<Range> Ranges(string name, SourceKind kind, string domain, params string[] cidrs)
    {
        var identity = new SourceIdentity(name, kind, domain);
        foreach (var cidr in cidrs)
        {
            var slash = cidr.IndexOf('/', StringComparison.Ordinal);
            yield return new Range(IPAddress.Parse(cidr[..slash]), int.Parse(cidr[(slash + 1)..], System.Globalization.CultureInfo.InvariantCulture), identity);
        }
    }

    private static bool Contains(IPAddress network, int prefix, IPAddress candidate)
    {
        if (network.AddressFamily != candidate.AddressFamily) { return false; }

        var a = network.GetAddressBytes();
        var b = candidate.GetAddressBytes();
        var whole = prefix / 8;

        for (var i = 0; i < whole; i++)
        {
            if (a[i] != b[i]) { return false; }
        }

        var rest = prefix % 8;
        if (rest == 0) { return true; }

        var mask = (byte)(0xFF << (8 - rest));
        return (a[whole] & mask) == (b[whole] & mask);
    }
}
