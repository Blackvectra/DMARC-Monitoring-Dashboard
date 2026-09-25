using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace DmarcMonitor.Core.Aggregate;

/// <summary>
/// Reads an address out of report text, strictly.
/// </summary>
/// <remarks>
/// <para>
/// An aggregate report is unauthenticated input: anybody who knows a domain's
/// rua address can mail it one, and every field in it is whatever they typed.
/// The source address is the field everything else hangs off - the pages, the
/// client report, and the indicator export a firewall reads, where
/// "0.0.0.0/0" is not a row but a rule. So it is taken only in the forms a
/// receiver actually writes.
/// </para>
/// <para>
/// Stricter than <see cref="IPAddress.TryParse(string?, out IPAddress?)"/>,
/// which accepts "127.1", "0x7f.0.0.1" and a scope id, none of which any
/// receiver emits and all of which read as a different address to whatever
/// consumes the text next.
/// </para>
/// </remarks>
public static partial class IpText
{
    /// <summary>True for a dotted-quad IPv4 or a plain IPv6 address; the parsed address in <paramref name="address"/>.</summary>
    public static bool TryParse(string? text, out IPAddress address)
    {
        address = IPAddress.None;

        var value = (text ?? "").Trim();
        if (value.Length == 0 || value.Length > 45) { return false; }

        if (value.Contains(':', StringComparison.Ordinal))
        {
            // No zone index: "fe80::1%eth0" names an interface on the
            // receiver's own machine, which is not a sender.
            if (value.Contains('%', StringComparison.Ordinal)) { return false; }

            if (!Ipv6Characters().IsMatch(value)
                || !IPAddress.TryParse(value, out var v6)
                || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            address = v6;
            return true;
        }

        if (!DottedQuad().IsMatch(value)
            || !IPAddress.TryParse(value, out var v4)
            || v4.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        // Each part at most 255 and without a leading zero, which some
        // readers take as octal: 010.0.0.1 is 8.0.0.1 to them and 10.0.0.1 to
        // others.
        foreach (var part in value.Split('.'))
        {
            if (part.Length > 1 && part[0] == '0') { return false; }
            if (int.Parse(part, System.Globalization.CultureInfo.InvariantCulture) > 255) { return false; }
        }

        address = v4;
        return true;
    }

    [GeneratedRegex(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", RegexOptions.CultureInvariant)]
    private static partial Regex DottedQuad();

    // Hex digits, colons, and dots for an embedded IPv4 tail (::ffff:1.2.3.4).
    [GeneratedRegex(@"^[0-9A-Fa-f:.]+$", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv6Characters();
}
