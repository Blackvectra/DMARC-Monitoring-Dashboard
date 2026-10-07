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
    /// the domain. The list is not a full public-suffix list - that is a
    /// dependency that goes stale - so a suffix it lacks reduces to the suffix
    /// itself. Naming a source from the result costs only a name, because an
    /// unmatched domain is not named; grouping on it costs more, which is why
    /// <see cref="LooksLikeAPublicSuffix"/> exists for the caller that groups.
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
    /// Whether a reduced domain is probably a registry rather than anybody's
    /// domain: two labels, a two-letter country code, and a first label of
    /// three letters or fewer, as in <c>ne.jp</c>, <c>co.kr</c> or
    /// <c>com.pg</c>.
    /// </summary>
    /// <remarks>
    /// For the caller that GROUPS on the reduced domain. The suffix list is
    /// short and cannot be complete, and a suffix it lacks reduces to the
    /// suffix itself - so two unrelated ISPs under it share one "domain", and
    /// a page built on that shows them as a single operator working through
    /// several customers. Declining to group costs a row that stays on its
    /// own, as it was before grouping; the other way costs a false finding.
    /// Deliberately blunt: a real two-letter domain under a country code, such
    /// as <c>ya.ru</c>, is caught too, and its hosts simply stay ungrouped.
    /// </remarks>
    public static bool LooksLikeAPublicSuffix(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) { return false; }

        var labels = domain.Trim().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);

        return labels.Length == 2
            && labels[1].Length == 2
            && labels[0].Length <= 3
            && labels[1].All(char.IsAsciiLetter);
    }

    /// <summary>
    /// The domain to treat a vendor as living at, when it answers from
    /// several: <c>googlemail.com</c> is <c>google.com</c>, and
    /// <c>contaboserver.net</c> is <c>contabo.net</c>. Any other domain is its
    /// own.
    /// </summary>
    /// <remarks>
    /// So one vendor is one sender however many of its domains an address
    /// reverses under. Only vendors the catalogue holds under more than one
    /// domain are listed; a vendor missing from this table is not merged,
    /// which is how it behaved before.
    /// </remarks>
    public static string CanonicalDomain(string domain) =>
        Aliases.TryGetValue(domain, out var main) ? main : domain;

    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["googlemail.com"] = "google.com",
        ["contaboserver.net"] = "contabo.net",
        ["hetzner.de"] = "hetzner.com",
        ["1and1.com"] = "ionos.com",
        ["mcsv.net"] = "mailchimp.com",
    };

    /// <summary>
    /// Suffixes that are not themselves anybody's domain.
    /// </summary>
    /// <remarks>
    /// The registries whose second-level names turn up in the reverse DNS of
    /// mail senders: the large ISP and hosting markets, where a failing-source
    /// list is full of residential ranges. It is not a full public-suffix list,
    /// which is a dependency that goes stale between releases; what it leaves
    /// out is caught by <see cref="LooksLikeAPublicSuffix"/> where it matters.
    /// </remarks>
    private static readonly HashSet<string> TwoPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Reverse zones. Without these, every address whose PTR is only its
        // own reverse name collapses into one bucket called "in-addr.arpa".
        "in-addr.arpa", "ip6.arpa",

        // Europe and Africa.
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk",
        "co.at", "or.at", "ac.at", "gv.at",
        "com.es", "nom.es", "org.es", "gob.es", "edu.es",
        "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
        "com.pt", "org.pt", "gov.pt", "edu.pt",
        "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
        "com.ro", "org.ro", "co.hu", "org.hu",
        "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua",
        "com.ru", "net.ru", "org.ru",
        "asso.fr", "com.fr", "gouv.fr",
        "co.za", "org.za", "net.za", "ac.za", "gov.za",
        "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
        "co.ke", "or.ke", "ne.ke", "ac.ke", "go.ke",
        "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
        "co.ma", "net.ma", "org.ma", "gov.ma",

        // Middle East and Asia.
        "co.il", "org.il", "net.il", "ac.il", "gov.il", "k12.il",
        "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
        "co.ae", "com.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr", "biz.tr", "info.tr",
        "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
        "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
        "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
        "com.lk", "com.np",
        "co.th", "in.th", "ac.th", "go.th", "or.th", "net.th",
        "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
        "co.id", "net.id", "or.id", "ac.id", "go.id", "web.id", "sch.id",
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
        "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "go.jp", "gr.jp", "ed.jp", "lg.jp",
        "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr", "ac.kr", "pe.kr",

        // Oceania.
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz", "geek.nz",

        // The Americas.
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "net.ar", "org.ar", "gob.ar", "gov.ar", "edu.ar",
        "com.co", "net.co", "org.co", "gov.co", "edu.co",
        "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
        "com.ve", "net.ve", "org.ve", "co.ve", "gob.ve",
        "com.ec", "net.ec", "org.ec", "gob.ec", "edu.ec",
        "com.uy", "net.uy", "org.uy", "edu.uy",
        "com.do", "com.gt", "com.pa", "com.sv", "com.ni", "com.hn", "com.py", "com.bo", "com.cu",
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
