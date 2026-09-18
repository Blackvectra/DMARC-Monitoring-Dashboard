using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Remediation;

/// <summary>What is being served at mta-sts.&lt;domain&gt;, if anything.</summary>
/// <param name="Reachable">
/// False when the file could not be fetched at all. Distinct from "fetched
/// and wrong", because the fixes differ: one is a web server that is not
/// there, the other is a file that is.
/// </param>
/// <param name="Policy">What was parsed from it, or null when it was not a policy.</param>
/// <param name="Problem">Why it could not be used, in words an operator can act on.</param>
public sealed record ServedPolicy(bool Reachable, MtaStsPolicy? Policy, string? Problem)
{
    public static ServedPolicy Missing(string problem) => new(false, null, problem);
}

/// <summary>
/// Publishing MTA-STS and TLS-RPT.
///
/// TLS-RPT is a TXT record and nothing else, so it can simply be published.
/// It is also the one to publish first: it is how you find out whether
/// anybody's mail is failing to connect securely, and MTA-STS without it is
/// enforcement with the lights off.
///
/// MTA-STS is two halves that have to agree - a TXT record, and a policy file
/// served over HTTPS at mta-sts.&lt;domain&gt; with a certificate that validates.
/// Only the first is DNS. So the rule throughout here is that the TXT record
/// is never published or advanced ahead of the file: announcing a policy id
/// for a file nobody can fetch is at best useless, and moving to enforce
/// against a file listing the wrong mail servers stops mail arriving.
/// </summary>
public static class TransportPlanner
{
    /// <summary>
    /// Plans the TLS-RPT record.
    /// </summary>
    /// <param name="reportingAddress">Where reports should go - the mailbox this tool reads.</param>
    public static ChangePlan TlsReporting(string domain, string? currentRecord, string reportingAddress)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(reportingAddress);

        var name = Name(domain, "_smtp._tls");
        var current = (currentRecord ?? "").Trim();
        var address = reportingAddress.Trim();

        if (!address.Contains('@', StringComparison.Ordinal))
        {
            return ChangePlan.Refused(domain, ChangeType.TlsRpt, name, current,
                $"'{reportingAddress}' is not an email address, so nothing would be able to report to it.");
        }

        var proposed = $"v=TLSRPTv1; rua=mailto:{address}";

        if (current.Length > 0 && !current.StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase))
        {
            return ChangePlan.Refused(domain, ChangeType.TlsRpt, name, current,
                $"The record at {name} is not a TLS-RPT record. Refusing to overwrite it.");
        }

        if (string.Equals(current, proposed, StringComparison.OrdinalIgnoreCase))
        {
            return new ChangePlan
            {
                Domain = domain, Type = ChangeType.TlsRpt, RecordName = name,
                CurrentValue = current, ProposedValue = current,
                Summary = $"{domain} already reports TLS failures to {address}",
            };
        }

        var warnings = new List<string>();
        if (current.Length > 0)
        {
            // Not a refusal: repointing reports at the mailbox this tool reads
            // is usually the whole intent. But somebody is already receiving
            // these and will stop.
            warnings.Add($"Reports currently go elsewhere ({current}). After this they go to {address} instead.");
        }

        return new ChangePlan
        {
            Domain = domain, Type = ChangeType.TlsRpt, RecordName = name,
            CurrentValue = current, ProposedValue = proposed,
            Warnings = warnings,
            Summary = current.Length == 0
                ? $"Publish TLS-RPT for {domain}, reporting to {address}"
                : $"Point {domain}'s TLS reports at {address}",
        };
    }

    /// <summary>
    /// Plans the MTA-STS TXT record for a policy that is already being served.
    /// </summary>
    /// <param name="served">What is actually at mta-sts.&lt;domain&gt; right now.</param>
    /// <param name="mailServers">The domain's live MX hosts, for checking the policy covers them.</param>
    public static ChangePlan MtaSts(
        string domain,
        string? currentRecord,
        ServedPolicy served,
        IReadOnlyList<string> mailServers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentNullException.ThrowIfNull(served);
        ArgumentNullException.ThrowIfNull(mailServers);

        var name = Name(domain, "_mta-sts");
        var current = (currentRecord ?? "").Trim();

        // The file first, always. A TXT record pointing at a policy that
        // cannot be fetched announces a promise nothing can keep.
        if (!served.Reachable || served.Policy is null)
        {
            return ChangePlan.Refused(domain, ChangeType.MtaSts, name, current,
                $"No usable policy is being served at https://mta-sts.{domain}/.well-known/mta-sts.txt "
                + $"({served.Problem ?? "it could not be read"}). Serve the policy first: a TXT record "
                + "announcing one that senders cannot fetch does nothing at all.");
        }

        var policy = served.Policy;

        if (current.Length > 0 && !current.StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase))
        {
            return ChangePlan.Refused(domain, ChangeType.MtaSts, name, current,
                $"The record at {name} is not an MTA-STS record. Refusing to overwrite it.");
        }

        var blockers = new List<string>();
        var warnings = new List<string>();

        // The id lives in the TXT record, never in the policy file, so it
        // cannot be recovered by fetching the file - and when nothing supplied
        // it, ToRecord() produced the literal "v=STSv1; id=". That is not a
        // valid record: RFC 8461 §3.1 requires 1 to 32 alphanumeric
        // characters, and a sender that cannot parse the TXT record treats the
        // domain as having no MTA-STS policy at all. Publishing it would have
        // switched transport security off for the domain while the page
        // reported the change as applied.
        if (!MtaStsPolicy.IsValidId(policy.Id))
        {
            blockers.Add(
                $"The policy id for {domain} is missing, so the record to announce it cannot be built. "
                + "The id lives in the TXT record rather than in the policy file, and it has to come from "
                + $"this product's own record of the policy. Run: dmarc mta-sts set --domain {domain}");
        }

        // The rule that matters. Enforce means a sender that reaches a host
        // this policy does not list gives up rather than delivering.
        if (string.Equals(policy.Mode, MtaStsMode.Enforce, StringComparison.OrdinalIgnoreCase))
        {
            if (mailServers.Count == 0)
            {
                blockers.Add(
                    $"The policy being served is in enforce mode and {domain}'s MX records could not be read, "
                    + "so there is no way to check it lists the right mail servers. Enforcing a policy that "
                    + "names the wrong hosts stops mail being delivered at all.");
            }
            else if (policy.Uncovered(mailServers) is { Count: > 0 } missing)
            {
                blockers.Add(
                    $"The policy being served is in enforce mode but does not cover {string.Join(", ", missing)}, "
                    + $"which {domain} publishes as a mail server. Senders would refuse to deliver there. "
                    + "Fix the policy file before announcing it.");
            }
        }
        else if (string.Equals(policy.Mode, MtaStsMode.Testing, StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add(
                "The policy is in testing mode, so a sender that cannot connect securely reports it and "
                + "delivers anyway. That is the right place to start; nothing is enforced until it moves.");

            if (mailServers.Count > 0 && policy.Uncovered(mailServers) is { Count: > 0 } notCovered)
            {
                // Harmless today, and the exact thing that would break on the
                // day somebody moves it to enforce.
                warnings.Add(
                    $"It does not cover {string.Join(", ", notCovered)}. Harmless in testing, and mail to "
                    + "those servers would stop the moment it is enforced.");
            }
        }

        var proposed = policy.ToRecord();

        if (string.Equals(current, proposed, StringComparison.OrdinalIgnoreCase))
        {
            return new ChangePlan
            {
                Domain = domain, Type = ChangeType.MtaSts, RecordName = name,
                CurrentValue = current, ProposedValue = current,
                Warnings = warnings,
                Summary = $"{domain} already announces the policy being served (id {policy.Id})",
            };
        }

        return new ChangePlan
        {
            Domain = domain, Type = ChangeType.MtaSts, RecordName = name,
            CurrentValue = current, ProposedValue = proposed,
            Blockers = blockers, Warnings = warnings,
            Summary = current.Length == 0
                ? $"Announce {domain}'s MTA-STS policy (mode {policy.Mode}, id {policy.Id})"
                : $"Update {domain}'s MTA-STS id to {policy.Id}, so senders fetch the policy again",
        };
    }

    /// <summary>
    /// Whether a domain's served policy is ready to move from testing to enforce.
    /// </summary>
    /// <remarks>
    /// The transport-security equivalent of advancing p=none to quarantine,
    /// and it wants the same thing first: evidence. TLS reports are that
    /// evidence, which is why TLS-RPT comes first. No reports means nobody has
    /// told you whether senders can connect securely, and enforcing on no
    /// evidence is how a domain stops receiving mail.
    /// </remarks>
    public static IReadOnlyList<string> WhatBlocksEnforcing(
        ServedPolicy served,
        IReadOnlyList<string> mailServers,
        bool tlsReportsArriving,
        int failedSessions)
    {
        ArgumentNullException.ThrowIfNull(served);
        ArgumentNullException.ThrowIfNull(mailServers);

        var blockers = new List<string>();

        if (!served.Reachable || served.Policy is null)
        {
            blockers.Add("No policy is being served, so there is nothing to enforce.");
            return blockers;
        }

        if (string.Equals(served.Policy.Mode, MtaStsMode.Enforce, StringComparison.OrdinalIgnoreCase))
        {
            return blockers;   // already there
        }

        if (!tlsReportsArriving)
        {
            blockers.Add(
                "No TLS reports have arrived, so there is no evidence about whether senders can reach this "
                + "domain securely. Publish TLS-RPT and collect a fortnight of reports first.");
        }

        if (failedSessions > 0)
        {
            blockers.Add(
                $"{failedSessions:N0} connection(s) have been reported as failing. Under enforce those "
                + "become undelivered mail rather than a line in a report.");
        }

        if (mailServers.Count == 0)
        {
            blockers.Add("The MX records could not be read, so the policy cannot be checked against them.");
        }
        else if (served.Policy.Uncovered(mailServers) is { Count: > 0 } missing)
        {
            blockers.Add($"The policy does not cover {string.Join(", ", missing)}.");
        }

        return blockers;
    }

    private static string Name(string domain, string prefix) =>
        $"{prefix}.{domain.Trim().TrimEnd('.').ToLowerInvariant()}";
}
