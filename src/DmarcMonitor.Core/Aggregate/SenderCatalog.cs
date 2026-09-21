using System.Net;
using System.Net.Sockets;

namespace DmarcMonitor.Core.Aggregate;

/// <summary>
/// Which service an address belongs to, when it is one anybody would
/// recognize.
/// </summary>
/// <remarks>
/// A client report used to list every sending address on its own. For a
/// mailbox on Microsoft 365 that is not a list of services, it is a list of
/// Microsoft's load balancers: one real domain's August had 630 "sources", of
/// which 618 were Microsoft and 12 were everything else. Fifteen of them were
/// printed and the other 606 became "and 606 more", which tells a customer
/// nothing and buries the twelve that matter.
///
/// Grouping needs a name for an address, and the honest ways to get one are
/// limited. Reverse DNS means a lookup per address while rendering a document,
/// which is slow, fails offline, and lets whoever controls the PTR record
/// choose what a customer's report says. The report already holds what the
/// sender authenticated as, but for a provider relaying the client's own mail
/// that is the client's own domain, so it does not separate Microsoft from
/// anybody else.
///
/// What is left is a table of the ranges the large providers publish, which is
/// what every other product in this space does. It is deliberately small:
/// these are the services a small-business book of domains actually sends
/// through, the ranges come from each provider's own SPF record, and anything
/// not listed keeps its address rather than being guessed at. A wrong name is
/// worse than an address, because "Microsoft 365" on a line that is really an
/// intruder reads as reassurance.
/// </remarks>
public static class SenderCatalog
{
    private static readonly (string Cidr, string Name)[] Ranges =
    [
        // Microsoft 365. The v6 prefixes carry most of the volume from a
        // mailbox hosted there, and the v4 /17s are the rest.
        ("40.92.0.0/15", "Microsoft 365"),
        ("40.107.0.0/16", "Microsoft 365"),
        ("52.100.0.0/14", "Microsoft 365"),
        ("104.47.0.0/17", "Microsoft 365"),
        ("2a01:111:f400::/48", "Microsoft 365"),
        ("2a01:111:f403::/48", "Microsoft 365"),

        ("209.85.128.0/17", "Google Workspace"),
        ("64.233.160.0/19", "Google Workspace"),
        ("66.102.0.0/20", "Google Workspace"),
        ("74.125.0.0/16", "Google Workspace"),
        ("142.250.0.0/15", "Google Workspace"),
        ("172.217.0.0/16", "Google Workspace"),
        ("2607:f8b0::/32", "Google Workspace"),

        ("149.72.0.0/16", "SendGrid"),
        ("167.89.0.0/17", "SendGrid"),
        ("168.245.0.0/17", "SendGrid"),
        ("198.37.144.0/20", "SendGrid"),

        ("198.2.128.0/18", "Mailchimp"),
        ("205.201.128.0/20", "Mailchimp"),
        ("148.105.0.0/16", "Mailchimp"),

        ("208.75.120.0/22", "Constant Contact"),

        ("67.231.144.0/20", "Proofpoint"),
        ("148.163.0.0/16", "Proofpoint"),

        ("205.139.110.0/24", "Mimecast"),
        ("91.220.42.0/24", "Mimecast"),

        ("54.240.0.0/18", "Amazon SES"),
        ("76.223.176.0/20", "Amazon SES"),

        ("136.143.128.0/17", "Zoho"),
        ("185.230.212.0/22", "Wix"),
        ("192.254.112.0/20", "Mailgun"),
        ("161.38.192.0/20", "Mailgun"),
        ("159.135.224.0/20", "Marketo"),
        ("13.111.0.0/16", "Salesforce"),
    ];

    private static readonly (byte[] Network, int Bits, AddressFamily Family, string Name)[] Parsed =
        [.. Ranges.Select(r =>
        {
            var slash = r.Cidr.IndexOf('/', StringComparison.Ordinal);
            var address = IPAddress.Parse(r.Cidr[..slash]);
            return (address.GetAddressBytes(), int.Parse(r.Cidr[(slash + 1)..], System.Globalization.CultureInfo.InvariantCulture),
                    address.AddressFamily, r.Name);
        })];

    /// <summary>
    /// The service that address belongs to, or null when it is not one this
    /// knows. Null means "print the address", never "unknown service".
    /// </summary>
    public static string? Identify(string? sourceIp)
    {
        if (string.IsNullOrWhiteSpace(sourceIp) || !IPAddress.TryParse(sourceIp.Trim(), out var ip))
        {
            return null;
        }

        var bytes = ip.GetAddressBytes();
        foreach (var (network, bits, family, name) in Parsed)
        {
            if (family == ip.AddressFamily && Contains(network, bits, bytes)) { return name; }
        }

        return null;
    }

    /// <summary>
    /// A name to group this address under: the service when it is known, and
    /// otherwise the address itself, so nothing is ever silently merged.
    /// </summary>
    public static string Label(string? sourceIp) =>
        Identify(sourceIp) ?? (sourceIp ?? "").Trim();

    private static bool Contains(byte[] network, int bits, byte[] address)
    {
        if (network.Length != address.Length) { return false; }

        var wholeBytes = bits / 8;
        for (var i = 0; i < wholeBytes; i++)
        {
            if (network[i] != address[i]) { return false; }
        }

        var remaining = bits % 8;
        if (remaining == 0) { return true; }

        // The partial byte: compare only the leading bits the prefix covers.
        var mask = (byte)(0xFF << (8 - remaining));
        return (network[wholeBytes] & mask) == (address[wholeBytes] & mask);
    }
}
