namespace DmarcMonitor.Core.Aggregate;

/// <summary>What a failing source most likely is.</summary>
public enum FailureKind
{
    /// <summary>
    /// Nobody can say. Unauthenticated, seen against this customer only, and
    /// named by nothing.
    /// </summary>
    /// <remarks>
    /// Its own answer rather than a lean towards the worst one. An address that
    /// cannot be named is not thereby hostile - it is as likely to be a service
    /// of the customer's that nobody wrote down - and calling it spoofing on
    /// no evidence is the same error as calling a record absent because the
    /// lookup timed out.
    /// </remarks>
    Unknown,

    /// <summary>
    /// A gateway that received the mail and sent it on, breaking it in transit.
    /// </summary>
    /// <remarks>
    /// The banner a security gateway staples to a message changes the body, so
    /// the DKIM signature no longer verifies, and the forwarding changes the
    /// envelope, so SPF no longer passes. DMARC fails on both, and nothing
    /// published in DNS can fix it - which is exactly why it has to be told
    /// apart from the rest. Read as a configuration fault, it sends an
    /// operator off to weaken a record that was never the problem.
    /// </remarks>
    Forwarded,

    /// <summary>
    /// A real service signing as itself rather than as the customer.
    /// </summary>
    /// <remarks>
    /// The signature verifies; it is over the wrong domain, so DMARC discards
    /// it. Fixable, and fixable at the vendor rather than in DNS.
    /// </remarks>
    Vendor,

    /// <summary>
    /// Unauthenticated, and sending as more than one unrelated customer.
    /// </summary>
    /// <remarks>
    /// The second half is what makes it a finding. One address failing against
    /// one customer is a daily occurrence and proves nothing; the same address
    /// against several unrelated customers of the same provider is one actor
    /// working through a book, and that pattern is only visible to somebody
    /// holding the whole book.
    /// </remarks>
    Spoofing,
}

/// <summary>What is known about one failing source, as far as one domain sees it.</summary>
public sealed record FailingSourceFacts
{
    public required string SourceIp { get; init; }

    /// <summary>Envelope domains SPF was checked against for this source.</summary>
    public IReadOnlyList<string> EnvelopeDomains { get; init; } = [];

    /// <summary>True when something this source signed actually verified.</summary>
    public bool Authenticated { get; init; }

    /// <summary>Messages from this source that passed DMARC for this domain.</summary>
    public long Passing { get; init; }

    /// <summary>Other clients this same address has been seen failing against.</summary>
    public int OtherClients { get; init; }

    /// <summary>The domain being judged.</summary>
    public string Domain { get; init; } = "";

    /// <summary>
    /// Signing domains the failing mail named, whether or not they verified.
    /// </summary>
    /// <remarks>
    /// What was attempted rather than what was proved, and the difference is
    /// the whole of the forwarding case: a message that left its sender signed
    /// and arrived broken still carries a signature header naming the sender,
    /// and a message that was never signed carries nothing.
    /// </remarks>
    public IReadOnlyList<string> SignedAsOnFailure { get; init; } = [];
}

/// <summary>
/// Tells a failing source that was broken in transit from one that is forging.
///
/// A DMARC failure is one number and it hides two opposite facts. Against a
/// real book of sixteen domains, half of every failure was a single security
/// gateway rewriting the customers' own mail, and a further slice was one
/// actor spoofing across seven of them. They need opposite responses, and both
/// currently render as the same red percentage - so a domain whose seven
/// messages were three real and four forged reads as "42.9% compliant", which
/// sounds like a broken domain and is not one.
///
/// Conservative in the same way as <see cref="SenderCatalog"/>, and for the
/// same reason: a wrong name is worse than no name. Nothing is called a
/// gateway on a guess, and nothing is called spoofing without the cross-client
/// evidence.
/// </summary>
public static class FailureClassifier
{
    /// <summary>
    /// The envelope domains security gateways send from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matched on the envelope domain rather than on an address, because the
    /// address list of a cloud gateway changes without notice and the domain it
    /// puts in MAIL FROM does not. Both of the gateways that account for the
    /// bulk of the failures on the real book are identifiable this way -
    /// <c>ipw.inkyphishfence.com</c> and <c>us.cloud-sec-av.com</c> - and an
    /// address table would have been stale within a month.
    /// </para>
    /// <para>
    /// Deliberately excludes <c>protection.outlook.com</c>. It is the envelope
    /// of Microsoft's own inbound relay and also part of the normal path for
    /// every Microsoft 365 tenant in the book, so matching it would file a
    /// great deal of ordinary mail as forwarded and quietly remove it from the
    /// compliance figure. Anything ambiguous is left to
    /// <see cref="FailureKind.Unknown"/>.
    /// </para>
    /// </remarks>
    private static readonly (string Suffix, string Name)[] Gateways =
    [
        ("inkyphishfence.com", "INKY Phish Fence"),
        ("cloud-sec-av.com", "a hosted mail security gateway"),
        ("shield.security", "a hosted mail security gateway"),
        ("mimecast.com", "Mimecast"),
        ("pphosted.com", "Proofpoint"),
        ("barracudanetworks.com", "Barracuda"),
        ("mailcontrol.com", "Forcepoint"),
        ("messagelabs.com", "Symantec Email Security"),
        ("antispamcloud.com", "SpamExperts"),
        ("mailspamprotection.com", "SiteGround Spam Protection"),
    ];

    public static FailureKind Classify(FailingSourceFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        // First, because it is the only one resting on a name rather than on a
        // pattern, and because a gateway that also signs something would
        // otherwise be filed as a vendor and stay in the compliance figure.
        if (GatewayName(facts.EnvelopeDomains) is not null) { return FailureKind.Forwarded; }

        // A verifying signature means a real sender that can be asked to sign
        // as the customer instead. Whoever it is, it is not forging: a forger
        // has no key anybody's resolver will accept.
        if (facts.Authenticated) { return FailureKind.Vendor; }

        // The shape a gateway leaves, and the one that actually identifies the
        // largest of them on real data. A hosted gateway does not put its own
        // name in the envelope - it re-sends the message with the customer's
        // own envelope domain, so the name table above never matches it. What
        // it does leave is the customer's signature header, now over a body it
        // has added a banner to: a signature naming this very domain that no
        // longer verifies.
        //
        // Paired with the address serving other clients too, because alone it
        // is also what a customer's own misconfigured signer looks like - same
        // domain, same broken signature - and that is a real fault of theirs
        // to fix rather than something to lift out of the compliance figure.
        // A shared relay carrying several unrelated customers' already-signed
        // mail is not that.
        if (facts.OtherClients > 0 && SignedAsThisDomain(facts)) { return FailureKind.Forwarded; }

        // Never from this domain's traffic alone. One address failing against
        // one customer is a daily occurrence.
        if (facts.Passing == 0 && facts.OtherClients > 0) { return FailureKind.Spoofing; }

        return FailureKind.Unknown;
    }

    /// <summary>
    /// True when the failing mail carried a signature naming the domain being
    /// judged, or a subdomain of it.
    /// </summary>
    /// <remarks>
    /// Subdomains count because a customer's bulk mail is routinely signed by
    /// a subdomain, and a relay that breaks it breaks it the same way.
    /// </remarks>
    private static bool SignedAsThisDomain(FailingSourceFacts facts)
    {
        var domain = facts.Domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (domain.Length == 0) { return false; }

        foreach (var signed in facts.SignedAsOnFailure)
        {
            var claimed = (signed ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (claimed.Length == 0) { continue; }

            if (claimed.Equals(domain, StringComparison.Ordinal)
                || claimed.EndsWith('.' + domain, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The gateway an envelope domain belongs to, or null when it is not one
    /// this knows.
    /// </summary>
    /// <remarks>
    /// Null means "no name", never "unknown gateway". Everything not in the
    /// table keeps its address and is judged on the pattern alone.
    /// </remarks>
    public static string? GatewayName(IReadOnlyList<string>? envelopeDomains)
    {
        if (envelopeDomains is null) { return null; }

        foreach (var envelope in envelopeDomains)
        {
            var domain = (envelope ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (domain.Length == 0) { continue; }

            foreach (var (suffix, name) in Gateways)
            {
                // Suffix on a label boundary, so a domain that merely ends in
                // the same letters is not matched.
                if (domain.Equals(suffix, StringComparison.Ordinal)
                    || domain.EndsWith('.' + suffix, StringComparison.Ordinal))
                {
                    return name;
                }
            }
        }

        return null;
    }

    /// <summary>One sentence saying what this kind of failure is, for a page or a report.</summary>
    public static string Explain(FailureKind kind) => kind switch
    {
        FailureKind.Forwarded =>
            "This domain's own signature was on the mail and no longer verifies, and the same relay carries "
            + "other customers' mail too. That is a gateway receiving the message and sending it on: the "
            + "banner it adds changes the body, so the signature breaks, and the forwarding changes the "
            + "envelope, so SPF stops passing. No DNS record can fix this.",
        FailureKind.Vendor =>
            "A real service signing as itself rather than as this domain. The signature verifies; DMARC "
            + "discards it because it is over the wrong domain. The fix is at the vendor.",
        FailureKind.Spoofing =>
            "Unauthenticated, and sending as other unrelated customers too. That is one actor working "
            + "through a book of domains rather than a service nobody recorded.",
        _ =>
            "Unauthenticated, and seen only against this domain. That is as likely to be a service nobody "
            + "wrote down as anything else, so it is worth identifying before it is treated as either.",
    };
}
