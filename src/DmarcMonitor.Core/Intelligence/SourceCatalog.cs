namespace DmarcMonitor.Core.Intelligence;

/// <summary>What a named sending source is, which decides how to read it failing.</summary>
public enum SourceKind
{
    /// <summary>Nothing is known about it. Not a judgement.</summary>
    Unknown,

    /// <summary>Somebody's mail platform. Microsoft 365, Google Workspace.</summary>
    MailProvider,

    /// <summary>
    /// A security product in the path. These BREAK mail rather than send it.
    /// </summary>
    /// <remarks>
    /// The single most useful thing to know about a failing address. A gateway
    /// staples a banner on, so the body changes and DKIM no longer verifies;
    /// it relays, so the envelope changes and SPF no longer passes. Nothing
    /// published in DNS fixes that, and read as a configuration fault it sends
    /// an operator off to weaken a record that was never the problem.
    /// </remarks>
    SecurityGateway,

    /// <summary>A service the customer sends campaigns or transactional mail through.</summary>
    /// <remarks>
    /// Fixable, and fixable at the vendor: they publish a way to sign as the
    /// customer's domain and somebody has not done it.
    /// </remarks>
    Marketing,

    /// <summary>A mailbox provider forwarding mail somebody redirected.</summary>
    Forwarder,

    /// <summary>
    /// Bulk hosting. Says who owns the wire, not who sent the mail.
    /// </summary>
    /// <remarks>
    /// Deliberately not "malicious". Plenty of legitimate mail leaves a VPS,
    /// and naming the host is a fact where calling it spoofing on no other
    /// evidence is a guess. It is a reason to look, not a verdict - the
    /// verdict comes from whether anything was signed and whether the same
    /// address is failing against other customers too.
    /// </remarks>
    Hosting,
}

/// <summary>A source, named.</summary>
/// <param name="Name">What to show a person instead of an address.</param>
/// <param name="Kind">What that thing is.</param>
/// <param name="Domain">The organizational domain it was matched on.</param>
public readonly record struct SourceIdentity(string Name, SourceKind Kind, string Domain);

/// <summary>
/// Turns a reverse-DNS name into something a person recognizes.
///
/// "35.174.145.124" tells an operator nothing and costs them a lookup;
/// "Avanan (Check Point Harmony)" tells them their own security gateway is
/// breaking their signatures. The whole difference between a table somebody
/// reads and a table somebody scrolls past.
///
/// The mechanism is deliberately the simple one, because it is the one that
/// works: take the PTR, reduce it to its organizational domain, look that up.
/// A commercial platform's export confirms the same shape - every source it
/// names resolves to one organizational domain, and mail-eastus2azlp170110003
/// .outbound.protection.outlook.com is matched as outlook.com exactly as it is
/// here. No address ranges to maintain and nothing to go stale, because DNS
/// moves when the vendor does.
///
/// What this is NOT is a threat feed. <see cref="SourceKind.Hosting"/> names
/// who owns the wire; it does not say the mail was hostile, and the judgement
/// about that stays where it already is - with whether anything was signed,
/// and whether the same address is failing against other customers too.
/// </summary>
public static class SourceCatalog
{
    /// <summary>
    /// Names an address from its reverse-DNS name. Null when nothing is known.
    /// </summary>
    public static SourceIdentity? Identify(string? reverseName)
    {
        var domain = OrganizationalDomain(reverseName);
        if (domain is null) { return null; }

        return Known.TryGetValue(domain, out var entry)
            ? new SourceIdentity(entry.Name, entry.Kind, domain)
            : null;
    }

    /// <summary>
    /// The registrable part of a host name: what <c>outlook.com</c> is to
    /// <c>mail-eastus2azlp170110003.outbound.protection.outlook.com</c>.
    /// </summary>
    /// <remarks>
    /// Two labels, with two exceptions that matter here.
    ///
    /// Reverse zones: <c>158.151.62.149.in-addr.arpa</c> reduced to
    /// <c>in-addr.arpa</c> would put every address on earth that has no real
    /// PTR into one bucket, so those keep a third label and stay distinct.
    ///
    /// Two-part public suffixes: <c>co.uk</c> and the rest are the suffix, not
    /// the domain. The list is short on purpose - a full public-suffix list is
    /// a dependency that goes stale, and being wrong here costs a name rather
    /// than a wrong answer, because an unmatched domain simply is not named.
    /// </remarks>
    public static string? OrganizationalDomain(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) { return null; }

        var labels = host.Trim().TrimEnd('.').ToLowerInvariant()
            .Split('.', StringSplitOptions.RemoveEmptyEntries);

        if (labels.Length < 2) { return null; }

        var lastTwo = string.Join('.', labels[^2..]);

        // A reverse zone, or a suffix that is not itself a registrable domain.
        // Either way the registrable part is one label further left, and there
        // has to be a label there to take.
        if (labels.Length >= 3 && TwoPartSuffixes.Contains(lastTwo))
        {
            return string.Join('.', labels[^3..]);
        }

        return lastTwo;
    }

    /// <summary>
    /// Suffixes that are not themselves anybody's domain.
    /// </summary>
    /// <remarks>
    /// Short on purpose. A full public-suffix list is a dependency that goes
    /// stale between releases, and the cost of being wrong here is only that a
    /// source goes unnamed - an organizational domain that matches nothing in
    /// the catalog is simply not named, never named wrongly. These are the
    /// ones that actually turn up in reverse DNS on this data.
    /// </remarks>
    private static readonly HashSet<string> TwoPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Reverse zones. Without these, every address whose PTR is only its
        // own reverse name collapses into one bucket called "in-addr.arpa".
        "in-addr.arpa", "ip6.arpa",

        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.nz", "co.za", "co.jp", "co.in",
        "com.br", "com.mx", "com.ar",
    };

    private readonly record struct Entry(string Name, SourceKind Kind);

    private static readonly Dictionary<string, Entry> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        // Mail platforms. Almost all legitimate mail arrives from one of these.
        ["outlook.com"]        = new("Microsoft 365", SourceKind.MailProvider),
        ["google.com"]         = new("Google", SourceKind.MailProvider),
        ["googlemail.com"]     = new("Google", SourceKind.MailProvider),
        ["zoho.com"]           = new("Zoho Mail", SourceKind.MailProvider),
        ["fastmail.com"]       = new("Fastmail", SourceKind.MailProvider),

        // Security gateways: the ones that break signatures in transit.
        ["cloud-sec-av.com"]   = new("Avanan (Check Point Harmony)", SourceKind.SecurityGateway),
        ["inkyphishfence.com"] = new("INKY", SourceKind.SecurityGateway),
        ["mimecast.com"]       = new("Mimecast", SourceKind.SecurityGateway),
        ["pphosted.com"]       = new("Proofpoint", SourceKind.SecurityGateway),
        ["ppe-hosted.com"]     = new("Proofpoint Essentials", SourceKind.SecurityGateway),
        ["iphmx.com"]          = new("Cisco IronPort", SourceKind.SecurityGateway),
        ["barracudanetworks.com"] = new("Barracuda", SourceKind.SecurityGateway),
        ["sonicwall.com"]      = new("SonicWall", SourceKind.SecurityGateway),
        ["trendmicro.com"]     = new("Trend Micro", SourceKind.SecurityGateway),
        ["mailcontrol.com"]    = new("Forcepoint", SourceKind.SecurityGateway),
        ["messagelabs.com"]    = new("Symantec Email Security", SourceKind.SecurityGateway),
        ["antispamcloud.com"]  = new("SpamExperts", SourceKind.SecurityGateway),
        ["mailspamprotection.com"] = new("SiteGround Spam Protection", SourceKind.SecurityGateway),

        // Named for what it is rather than for who runs it: the envelope
        // domain is all there is to go on and several products use it.
        ["shield.security"]    = new("a hosted mail security gateway", SourceKind.SecurityGateway),

        // Services a customer sends through. Fixable at the vendor.
        ["sendgrid.net"]       = new("SendGrid", SourceKind.Marketing),
        ["sparkpostmail.com"]  = new("SparkPost", SourceKind.Marketing),
        ["mcsv.net"]           = new("Mailchimp", SourceKind.Marketing),
        ["mailchimp.com"]      = new("Mailchimp", SourceKind.Marketing),
        ["meltwater.com"]      = new("Meltwater", SourceKind.Marketing),
        ["constantcontact.com"] = new("Constant Contact", SourceKind.Marketing),
        ["myngp.com"]          = new("NGP VAN", SourceKind.Marketing),
        ["salesforce.com"]     = new("Salesforce", SourceKind.Marketing),
        ["netsuite.com"]       = new("NetSuite", SourceKind.Marketing),
        ["amazonses.com"]      = new("Amazon SES", SourceKind.Marketing),
        ["mailgun.net"]        = new("Mailgun", SourceKind.Marketing),
        ["postmarkapp.com"]    = new("Postmark", SourceKind.Marketing),
        ["intuit.com"]         = new("Intuit", SourceKind.Marketing),

        // Bulk hosting. Who owns the wire, not who sent the mail.
        ["colocrossing.com"]   = new("ColoCrossing", SourceKind.Hosting),
        ["contabo.net"]        = new("Contabo", SourceKind.Hosting),
        ["contaboserver.net"]  = new("Contabo", SourceKind.Hosting),
        ["digitalocean.com"]   = new("DigitalOcean", SourceKind.Hosting),
        ["ovh.net"]            = new("OVH", SourceKind.Hosting),
        ["hetzner.de"]         = new("Hetzner", SourceKind.Hosting),
        ["hetzner.com"]        = new("Hetzner", SourceKind.Hosting),
        ["linode.com"]         = new("Linode", SourceKind.Hosting),
        ["vultr.com"]          = new("Vultr", SourceKind.Hosting),
        ["amazonaws.com"]      = new("Amazon Web Services", SourceKind.Hosting),
        ["ionos.com"]          = new("IONOS", SourceKind.Hosting),
        ["1and1.com"]          = new("IONOS", SourceKind.Hosting),
    };
}
