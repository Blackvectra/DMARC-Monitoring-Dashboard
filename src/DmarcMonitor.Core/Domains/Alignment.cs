namespace DmarcMonitor.Core.Domains;

/// <summary>
/// How a domain that authenticated relates to the domain in the From header.
/// </summary>
public enum AlignmentVerdict
{
    /// <summary>An exact match. Aligns whether alignment is strict or relaxed.</summary>
    Exact,

    /// <summary>
    /// A subdomain relation: aligns under relaxed alignment, and does not
    /// under strict.
    /// </summary>
    Organizational,

    /// <summary>
    /// A different organisation altogether. Never aligns, in either mode, so
    /// the only fix is to change what the sender signs as.
    /// </summary>
    Unrelated,
}

/// <summary>
/// The distinction DMARC turns on and nothing in this product said out loud:
/// a signature can be perfectly valid and still count for nothing.
/// </summary>
/// <remarks>
/// <para>
/// DKIM verifying proves the message was signed by whoever controls the <c>d=</c>
/// domain. DMARC additionally requires that domain to line up with the one in
/// the From header - RFC 7489 §3.1. A vendor signing its own domain satisfies
/// the first and fails the second, and the report row for it says
/// <c>dkim=pass</c> beside <c>dmarc=fail</c>, which reads like a contradiction
/// unless somebody explains it.
/// </para>
/// <para>
/// It is worth saying because the two failures have opposite fixes. An unsigned
/// source needs DKIM turning on. A source signing as itself already has DKIM
/// on, correctly, for the wrong domain - and telling its operator to "set up
/// DKIM" sends them to look at something that is already working.
/// </para>
/// </remarks>
public static class Alignment
{
    /// <summary>
    /// Classifies a domain that authenticated against the From domain.
    /// </summary>
    /// <remarks>
    /// The organisational comparison is a suffix test rather than a Public
    /// Suffix List lookup. For the case this exists to catch - a subdomain of
    /// the customer's own domain, against the customer's own domain - the two
    /// agree, and shipping a PSL means shipping a list that goes stale.
    /// Where they can disagree is a name under a public suffix that is itself
    /// two labels, <c>foo.github.io</c> against <c>github.io</c>, which this
    /// calls organisational and the PSL calls unrelated. Nothing acts on that
    /// verdict by itself: it produces a sentence telling an operator the two
    /// names look related and to confirm the subdomain is theirs.
    /// </remarks>
    public static AlignmentVerdict Classify(string authenticatedDomain, string fromDomain)
    {
        var auth = Normalise(authenticatedDomain);
        var from = Normalise(fromDomain);

        if (auth.Length == 0 || from.Length == 0) { return AlignmentVerdict.Unrelated; }
        if (string.Equals(auth, from, StringComparison.Ordinal)) { return AlignmentVerdict.Exact; }

        // Either direction. A domain signing as its own parent is as aligned
        // under relaxed as a parent signing as its child.
        return IsSubdomainOf(auth, from) || IsSubdomainOf(from, auth)
            ? AlignmentVerdict.Organizational
            : AlignmentVerdict.Unrelated;
    }

    /// <summary>True when the domain aligns under the given mode.</summary>
    public static bool Aligns(string authenticatedDomain, string fromDomain, bool strict) =>
        Classify(authenticatedDomain, fromDomain) switch
        {
            AlignmentVerdict.Exact => true,
            AlignmentVerdict.Organizational => !strict,
            _ => false,
        };

    private static bool IsSubdomainOf(string candidate, string parent) =>
        candidate.Length > parent.Length + 1
        && candidate.EndsWith(parent, StringComparison.Ordinal)
        // On a label boundary. Without this, "notacme.com" is a subdomain of
        // "acme.com", and a lookalike domain gets described as the customer's
        // own infrastructure.
        && candidate[candidate.Length - parent.Length - 1] == '.';

    private static string Normalise(string domain) =>
        string.IsNullOrWhiteSpace(domain) ? "" : domain.Trim().TrimEnd('.').ToLowerInvariant();
}
