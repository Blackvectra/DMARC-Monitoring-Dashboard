using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Remediation;

/// <summary>One record somebody has to publish, ready to be copied.</summary>
public sealed record RecordToPublish(string Name, string Type, string Value)
{
    /// <summary>What it is for, in a sentence, for the operator reading it.</summary>
    public string Why { get; init; } = "";

    /// <summary>
    /// True when this product can write it through a configured DNS provider.
    /// </summary>
    /// <remarks>
    /// The CNAME cannot be, in general: it points at wherever this instance is
    /// reachable, which the product does not know from DNS and will not guess.
    /// </remarks>
    public bool CanBeAutomated { get; init; } = true;
}

/// <summary>
/// The records a domain needs for transport security, as records.
///
/// Separate from TransportPlanner, which decides whether a change is SAFE to
/// apply. This answers the earlier question: what has to exist at all. For
/// TLS-RPT that is one record. For MTA-STS it is three things, and the reason
/// the feature was hard to finish is that only one of them is a DNS record the
/// product can write:
///
///   1. mta-sts.&lt;domain&gt; has to resolve to wherever this app is served, over
///      HTTPS with a certificate valid for THAT name, because a sender fetches
///      the policy from it and will not follow a redirect or accept a bad
///      certificate.
///   2. The policy file has to be served there. This app does that itself,
///      from the Host header, once the name points at it.
///   3. Only then does the TXT record at _mta-sts.&lt;domain&gt; mean anything.
///      Announcing a policy that is not being served is worse than announcing
///      nothing: senders cache the failure.
///
/// Published in that order, and the product refuses to announce step 3 until
/// step 2 answers - which is why an operator who only ever saw "no MTA-STS
/// policy" had no way to find out what to do about it.
/// </summary>
public static class TransportSetup
{
    /// <summary>The one record TLS-RPT needs.</summary>
    /// <remarks>
    /// Safe on its own and worth doing first. It asks receivers to report
    /// failed or downgraded TLS connections and changes nothing about
    /// delivery, so it is the evidence that makes the MTA-STS decision
    /// possible rather than a guess.
    /// </remarks>
    public static RecordToPublish TlsReporting(string domain, string reportingAddress)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(reportingAddress);

        return new RecordToPublish(
            $"_smtp._tls.{domain.Trim().TrimEnd('.')}",
            "TXT",
            $"v=TLSRPTv1; rua=mailto:{reportingAddress.Trim()}")
        {
            Why = "Asks receivers to report failed or downgraded TLS connections. "
                + "Changes nothing about delivery, so there is no risk in publishing it.",
        };
    }

    /// <summary>
    /// Everything MTA-STS needs, in the order it has to be published.
    /// </summary>
    /// <param name="policyHost">
    /// Where this instance is reachable, e.g. dmarc.nextlayersec.ai. The CNAME
    /// target. Null or empty when nobody has configured it, in which case the
    /// record is still listed - with the target named as unknown rather than
    /// guessed, because a CNAME pointed at the wrong host is a policy nobody
    /// can fetch.
    /// </param>
    public static IReadOnlyList<RecordToPublish> MtaSts(string domain, string? policyHost, MtaStsPolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentNullException.ThrowIfNull(policy);

        var name = domain.Trim().TrimEnd('.');
        var target = string.IsNullOrWhiteSpace(policyHost)
            ? "<the host this app is served from>"
            : policyHost.Trim().TrimEnd('.');

        return
        [
            new RecordToPublish($"mta-sts.{name}", "CNAME", target)
            {
                Why = $"So a sender can fetch the policy from https://mta-sts.{name}/.well-known/mta-sts.txt. "
                    + "That host needs a certificate valid for this name; a sender will not follow a "
                    + "redirect or accept a bad one.",

                // Writable in principle, but only once somebody has said where
                // this instance actually lives, and getting it wrong means a
                // policy nobody can fetch.
                CanBeAutomated = !string.IsNullOrWhiteSpace(policyHost),
            },
            new RecordToPublish($"_mta-sts.{name}", "TXT", policy.ToRecord())
            {
                Why = "Announces that a policy exists and which version it is. Publish this LAST: "
                    + "announcing a policy that is not yet being served is worse than announcing nothing, "
                    + "because senders cache the failure.",
            },
        ];
    }

    /// <summary>
    /// The policy file itself, which is served rather than published in DNS.
    /// </summary>
    /// <remarks>
    /// Returned alongside the records because an operator looking at the CNAME
    /// needs to know what will be at the end of it, and because a domain whose
    /// policy this product does not serve needs the text to host elsewhere.
    /// </remarks>
    public static string PolicyFile(MtaStsPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return policy.ToFile();
    }
}
