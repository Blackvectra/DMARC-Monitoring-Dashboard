namespace DmarcMonitor.Core.Dns;

/// <summary>How much a finding matters.</summary>
public enum HygieneSeverity
{
    /// <summary>Worth doing when somebody is already in the record.</summary>
    Tidy,

    /// <summary>A real weakness, but nothing is broken today.</summary>
    Weakness,

    /// <summary>Mail is failing, or will the next time anything changes.</summary>
    Breaking,
}

/// <summary>One thing wrong, or missing, in a domain's published records.</summary>
public sealed record HygieneFinding
{
    public required HygieneSeverity Severity { get; init; }

    /// <summary>Which record this is about: SPF, DMARC, DKIM, MTA-STS, TLS-RPT.</summary>
    public required string Record { get; init; }

    /// <summary>What is wrong, in one sentence.</summary>
    public required string Problem { get; init; }

    /// <summary>What to do about it.</summary>
    public required string Fix { get; init; }

    /// <summary>
    /// Where the rule comes from.
    /// </summary>
    /// <remarks>
    /// An RFC section or a named publication, so an operator can show a client
    /// the rule rather than asking them to take our word for it. Only cited
    /// where it is genuinely the source of the rule; a made-up control number
    /// is worse than none, because the first person to look it up stops
    /// trusting every other citation in the document.
    /// </remarks>
    public string Reference { get; init; } = "";
}

/// <summary>What DNS currently publishes for a domain.</summary>
public sealed record PublishedRecords
{
    public required string Domain { get; init; }

    /// <summary>Every TXT record at the apex that begins v=spf1. More than one is itself a fault.</summary>
    public IReadOnlyList<string> SpfRecords { get; init; } = [];

    /// <summary>The TXT record at _dmarc, if there is one.</summary>
    public string? DmarcRecord { get; init; }

    /// <summary>The TXT record at _mta-sts, if there is one.</summary>
    public string? MtaStsRecord { get; init; }

    /// <summary>The TXT record at _smtp._tls, if there is one.</summary>
    public string? TlsRptRecord { get; init; }

    /// <summary>Include targets that resolved to no SPF record at all.</summary>
    public IReadOnlyList<string> DeadIncludes { get; init; } = [];

    /// <summary>
    /// DNS lookups evaluating the SPF record really costs, includes followed.
    /// </summary>
    /// <remarks>
    /// Zero when nothing resolved it. Counting terms in the record instead
    /// understates it badly: one include of a large provider is a single term
    /// and half a dozen lookups.
    /// </remarks>
    public int SpfLookups { get; init; }

    /// <summary>True when the lookup itself failed, so absence proves nothing.</summary>
    public bool LookupFailed { get; init; }
}

/// <summary>What the reports say is actually happening, for cross-referencing.</summary>
public sealed record ObservedSending
{
    /// <summary>MTA-STS mode seen in TLS reports: enforce, testing, none.</summary>
    public string MtaStsMode { get; init; } = "";

    /// <summary>True when any TLS report has ever arrived for this domain.</summary>
    public bool TlsReportsArriving { get; init; }

    /// <summary>DKIM selectors seen signing successfully. These must keep existing.</summary>
    public IReadOnlyList<string> WorkingSelectors { get; init; } = [];

    /// <summary>Messages seen in the window, so a silent domain is not judged on nothing.</summary>
    public long Messages { get; init; }

    /// <summary>
    /// Days of reports actually held for this domain.
    /// </summary>
    /// <remarks>
    /// The real span, not a configured window. It decides whether "nothing has
    /// been seen" means anything at all: two days of reports say nothing about
    /// a service that bills monthly, and quoting a fixed thirty days over two
    /// days of evidence would be inventing the evidence.
    /// </remarks>
    public int WindowDays { get; init; }

    /// <summary>What each include in the SPF record is for, and whether it has sent.</summary>
    public IReadOnlyList<IncludeUsage> Includes { get; init; } = [];
}

/// <summary>
/// Reads a domain's published records and says what is wrong with them.
///
/// Pure, so every combination can be tested rather than eyeballed against one
/// live domain. It is deliberately conservative: an operator acts on this by
/// editing a customer's DNS, and a wrong recommendation there breaks mail for
/// a business. Anything that cannot be established from the record and the
/// reports together is left unsaid rather than guessed at.
/// </summary>
public static class DnsHygiene
{
    /// <summary>
    /// RFC 7208 section 4.6.4. Exceeding it is a permerror, and a permerror
    /// means SPF does not pass - so the limit is a cliff rather than a budget.
    /// </summary>
    public const int SpfLookupLimit = 10;

    /// <summary>Close enough to the cliff that the next include pushes it over.</summary>
    public const int SpfLookupWarnAt = 8;

    /// <summary>
    /// Reports needed before silence from an include means anything.
    /// </summary>
    /// <remarks>
    /// A full month, because the services that sit in an SPF record and send
    /// rarely - accounting, payroll, an annual renewal notice - are exactly
    /// the ones somebody would wrongly delete. Below this the honest finding
    /// is no finding.
    /// </remarks>
    public const int MinimumDaysToJudgeAnInclude = 30;

    public static IReadOnlyList<HygieneFinding> Assess(PublishedRecords published, ObservedSending observed)
    {
        ArgumentNullException.ThrowIfNull(published);
        ArgumentNullException.ThrowIfNull(observed);

        // A failed lookup is not an absent record. Reporting "no DMARC record"
        // because the resolver timed out would have somebody publishing a
        // second one over the top of a working first.
        if (published.LookupFailed)
        {
            return
            [
                new HygieneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "DNS",
                    Problem = "The records for this domain could not be read, so nothing below was checked.",
                    Fix = "Check the domain still resolves, then run this again.",
                },
            ];
        }

        var findings = new List<HygieneFinding>();

        Spf(findings, published);
        Includes(findings, observed);
        Dmarc(findings, published);
        TransportSecurity(findings, published, observed);

        // Worst first, and within a severity in the order they were found, so
        // the SPF problems stay together rather than interleaving.
        return [.. findings.OrderByDescending(f => f.Severity)];
    }

    // ---- SPF -----------------------------------------------------------------

    private static void Spf(List<HygieneFinding> findings, PublishedRecords published)
    {
        if (published.SpfRecords.Count == 0)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "SPF",
                Problem = "No SPF record is published.",
                Fix = "Publish a TXT record at the domain apex listing the services allowed to send, "
                    + "ending in -all once the list is complete.",
                Reference = "RFC 7208; NIST SP 800-177 Rev. 1",
            });
            return;
        }

        if (published.SpfRecords.Count > 1)
        {
            // Not a style problem. Two records is a permerror, and a permerror
            // means SPF does not pass for anybody.
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "SPF",
                Problem = $"{published.SpfRecords.Count} SPF records are published. A domain may have one. "
                        + "Receivers treat more than one as an error and SPF fails for every sender.",
                Fix = "Merge them into a single record and delete the rest.",
                Reference = "RFC 7208 §4.5",
            });
        }

        var record = SpfRecord.Parse(published.SpfRecords[0]);
        if (!record.IsValid) { return; }

        // The resolved figure when there is one, and the floor otherwise, so
        // this still says something useful without a resolver.
        var lookups = published.SpfLookups > 0 ? published.SpfLookups : record.DirectLookups;

        if (lookups > SpfLookupLimit)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "SPF",
                Problem = $"The record needs {lookups} DNS lookups and the limit is "
                        + $"{SpfLookupLimit}. Over the limit SPF returns an error, which is not a pass, so "
                        + "mail that should authenticate does not.",
                Fix = "Remove services that no longer send, or replace an include with the addresses it "
                    + "resolves to. Each ip4 or ip6 term is free.",
                Reference = "RFC 7208 §4.6.4",
            });
        }
        else if (lookups >= SpfLookupWarnAt)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "SPF",
                Problem = $"The record uses {lookups} of the {SpfLookupLimit} DNS lookups allowed, counting "
                        + "what each include pulls in. Adding one more service may break it.",
                Fix = "Tidy it before the next service is added rather than after.",
                Reference = "RFC 7208 §4.6.4",
            });
        }

        foreach (var dead in published.DeadIncludes)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "SPF",
                Problem = $"include:{dead} resolves to no SPF record. It authorises nothing and still "
                        + "spends one of the ten lookups.",
                Fix = $"Remove include:{dead}.",
                Reference = "RFC 7208 §4.6.4",
            });
        }

        var all = record.All;
        if (all is null)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "SPF",
                Problem = "The record has no all mechanism, so it says nothing about senders it does not list.",
                Fix = "End the record with -all once the list of senders is complete.",
                Reference = "RFC 7208 §5.1",
            });
        }
        else if (all.Qualifier == '+')
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "SPF",
                Problem = "The record ends in +all, which authorises every address on the internet to send "
                        + "as this domain. It is worse than having no SPF record.",
                Fix = "Change it to -all.",
                Reference = "RFC 7208 §5.1",
            });
        }
        else if (all.Qualifier == '?')
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "SPF",
                Problem = "The record ends in ?all, which is neutral: it makes no statement about senders "
                        + "it does not list, so SPF protects nothing.",
                Fix = "Change it to -all once the list of senders is known to be complete.",
                Reference = "RFC 7208 §5.1",
            });
        }

        if (record.Terms.Any(t => t.Name == "ptr"))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "SPF",
                Problem = "The record uses the ptr mechanism, which the standard says should not be used: "
                        + "it is slow, unreliable, and some receivers ignore it.",
                Fix = "Replace it with the addresses or includes for the services that actually send.",
                Reference = "RFC 7208 §5.5",
            });
        }
    }

    /// <summary>
    /// What each include is for, and whether anything has come from it.
    /// </summary>
    /// <remarks>
    /// The one finding here that must never become an instruction. A service
    /// can be real and legitimately quiet: accounting software that sends at
    /// quarter end, a payroll provider that sends monthly, a backup alerting
    /// system that has had nothing to report. Thirty days of silence from any
    /// of those is normal, and an operator who deletes the include on that
    /// basis breaks the mail that matters most precisely when it is next sent.
    ///
    /// So this states the evidence and the window, names the service, and
    /// leaves the decision with somebody who knows whether the business still
    /// uses it. It also counts against the reports rather than against DNS: an
    /// include seen sending is proven in use, which is the direction of this
    /// check that CAN be relied on.
    /// </remarks>
    private static void Includes(List<HygieneFinding> findings, ObservedSending observed)
    {
        // Not enough history to say anything. Silence over a fortnight is
        // what a monthly service looks like.
        if (observed.WindowDays < MinimumDaysToJudgeAnInclude) { return; }

        foreach (var include in observed.Includes.Where(i => i.Unused && !i.ResolvedNothing))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "SPF",
                Problem = $"include:{include.Target} ({include.Service}) authorises "
                        + $"{include.Ranges.Count} address range(s) and no mail has been seen from any of "
                        + $"them in the {observed.WindowDays} days of reports held. It still costs a DNS lookup.",
                Fix = $"Confirm the business no longer uses {include.Service} before removing it. Plenty "
                    + "of services send monthly or at quarter end, so this is evidence rather than an "
                    + "instruction, and the safe order is to ask first and edit second.",
                Reference = "RFC 7208 §4.6.4",
            });
        }
    }

    // ---- DMARC ---------------------------------------------------------------

    private static void Dmarc(List<HygieneFinding> findings, PublishedRecords published)
    {
        if (string.IsNullOrWhiteSpace(published.DmarcRecord))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "DMARC",
                Problem = "No DMARC record is published, so nobody is told what to do with mail that fails "
                        + "the checks, and no reports are sent.",
                Fix = "Publish a TXT record at _dmarc starting at p=none with a rua address, and move to "
                    + "quarantine then reject once the reports show what sends legitimately.",
                Reference = "RFC 7489; NIST SP 800-177 Rev. 1",
            });
            return;
        }

        var tags = ParseTags(published.DmarcRecord);

        if (!tags.ContainsKey("rua"))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "DMARC",
                Problem = "The record has no rua address, so no aggregate reports are sent and there is no "
                        + "way to see what is sending as this domain.",
                Fix = "Add rua=mailto: pointing at the reporting mailbox.",
                Reference = "RFC 7489 §6.3",
            });
        }

        if (tags.TryGetValue("pct", out var pct) && int.TryParse(pct, out var percent) && percent < 100)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "DMARC",
                Problem = $"pct={percent}, so the policy is applied to {percent}% of failing mail and the "
                        + $"other {100 - percent}% is delivered regardless. The domain reads as protected "
                        + "in any summary that shows only the policy.",
                Fix = "Raise it to 100 once the failures have been dealt with.",
                Reference = "RFC 7489 §6.3",
            });
        }

        // sp matters because subdomains inherit p only when sp is absent, and
        // an explicit weaker sp is a hole somebody opened deliberately and
        // then forgot.
        if (tags.TryGetValue("sp", out var sp) && tags.TryGetValue("p", out var p)
            && Strength(sp) < Strength(p))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "DMARC",
                Problem = $"The domain is at p={p} but subdomains are at sp={sp}, so anything sent from a "
                        + "subdomain is treated more leniently than the domain itself.",
                Fix = $"Set sp={p}, or remove sp so subdomains inherit the domain's policy.",
                Reference = "RFC 7489 §6.3",
            });
        }
    }

    // ---- transport -----------------------------------------------------------

    private static void TransportSecurity(
        List<HygieneFinding> findings, PublishedRecords published, ObservedSending observed)
    {
        if (string.IsNullOrWhiteSpace(published.MtaStsRecord))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "MTA-STS",
                Problem = "No MTA-STS policy is published, so a sending server has no way to know that mail "
                        + "for this domain must go over an encrypted, verified connection.",
                Fix = "Publish a policy file and the _mta-sts TXT record, starting in testing mode.",
                Reference = "RFC 8461; NIST SP 800-177 Rev. 1",
            });
        }
        else if (string.Equals(observed.MtaStsMode, "Testing", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "MTA-STS",
                Problem = "The policy is in testing mode. A sending server reports a connection that does "
                        + "not match it and delivers the mail anyway, so nothing is actually enforced.",
                Fix = "Move the policy to enforce once the reports show no failures.",
                Reference = "RFC 8461 §5",
            });
        }

        if (string.IsNullOrWhiteSpace(published.TlsRptRecord))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "TLS-RPT",
                Problem = observed.TlsReportsArriving
                    ? "No TLS-RPT record is published, yet TLS reports are arriving - so they are being sent "
                      + "somewhere other than here."
                    : "No TLS-RPT record is published, so nobody reports failed or downgraded connections.",
                Fix = "Publish a TXT record at _smtp._tls pointing at the reporting mailbox.",
                Reference = "RFC 8460",
            });
        }
    }

    // ---- helpers -------------------------------------------------------------

    /// <summary>Splits a DMARC record into its tags. Tolerant of spacing, as records in the wild are.</summary>
    private static Dictionary<string, string> ParseTags(string record)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in record.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) { continue; }

            tags[part[..equals].Trim()] = part[(equals + 1)..].Trim();
        }

        return tags;
    }

    private static int Strength(string policy) => policy.ToLowerInvariant() switch
    {
        "reject" => 3,
        "quarantine" => 2,
        "none" => 1,
        _ => 0,
    };
}
