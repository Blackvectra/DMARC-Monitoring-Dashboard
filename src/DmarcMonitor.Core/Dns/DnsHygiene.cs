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

    /// <summary>
    /// Every TXT record at the apex, SPF or not.
    /// </summary>
    /// <remarks>
    /// Kept because the records that are not SPF are sometimes the finding.
    /// A TXT record that lists includes and ends in -all, with no v=spf1 in
    /// front of it, is invisible to <see cref="SpfRecords"/> by design and is
    /// the reason a domain with an SPF record in its zone has no SPF at all.
    /// <see cref="ZoneAudit"/> needs to see it here to confirm that what a
    /// zone file shows is still what DNS serves.
    /// </remarks>
    public IReadOnlyList<string> ApexTxt { get; init; } = [];

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

    /// <summary>
    /// The policy file actually served at mta-sts.&lt;domain&gt;, or null when
    /// nobody fetched it.
    /// </summary>
    /// <remarks>
    /// Null and "could not be reached" are different answers here, exactly as
    /// they are for a DNS lookup. Null means this run did not ask - an offline
    /// caller, or a domain with no _mta-sts record worth asking about - and
    /// nothing may be concluded from it. A <see cref="ServedPolicy"/> that is
    /// not reachable is a real answer, and a serious one: the domain announces
    /// a policy it is not serving.
    /// </remarks>
    public DmarcMonitor.Core.Remediation.ServedPolicy? ServedMtaSts { get; init; }

    /// <summary>
    /// The domain's mail servers, best preference first. Empty means the
    /// lookup did not answer, never that there are none.
    /// </summary>
    public IReadOnlyList<string> MxHosts { get; init; } = [];

    /// <summary>True when the lookup itself failed, so absence proves nothing.</summary>
    public bool LookupFailed { get; init; }

    /// <summary>
    /// True when the resolver answered that the name does not exist.
    /// </summary>
    /// <remarks>
    /// A third answer, distinct from both of the others. The lookup did not
    /// fail and the records are not merely absent: there is no domain. Without
    /// this the two look identical - an NXDOMAIN returns no answers, just as a
    /// domain with no TXT records does - and a mistyped customer domain came
    /// back with a confident list of weaknesses and instructions to publish
    /// records at an apex that does not exist.
    /// </remarks>
    public bool DomainDoesNotExist { get; init; }
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

        // Nor is a domain that does not exist a domain with no records. There
        // is nothing to publish a record on, and every finding below would be
        // an instruction to edit a zone nobody owns. For an MSP checking a
        // customer domain, this is a typo, and saying so is the whole answer.
        if (published.DomainDoesNotExist)
        {
            return
            [
                new HygieneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "DNS",
                    Problem = $"There is no domain called {published.Domain}. The resolver says the name does not exist, so nothing below was checked.",
                    Fix = "Check the spelling. If the domain is new, it may not have been delegated yet.",
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
                Problem = $"include:{dead} resolves to no SPF record. It authorizes nothing and still "
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
                Problem = "The record ends in +all, which authorizes every address on the internet to send "
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
                Problem = $"include:{include.Target} ({include.Service}) authorizes "
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

        // The same parser the domain page uses, so the page and the check
        // cannot disagree about what a record says.
        var record = DmarcRecord.Parse(published.DmarcRecord);
        if (!record.IsValid) { return; }

        if (record.Rua.Length == 0)
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

        if (record.Percent < 100)
        {
            var percent = record.Percent;
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
        if (record.SubdomainPolicy.Length > 0 && Strength(record.SubdomainPolicy) < Strength(record.Policy))
        {
            var sp = record.SubdomainPolicy;
            var p = record.Policy;
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
        else
        {
            MtaStsServed(findings, published, observed);
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

    /// <summary>
    /// Judges the policy a domain is serving, not the one senders remember.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This used to read the mode off the newest row in tls_reports, which is
    /// what senders observed when they last wrote, and the two diverge the
    /// moment anybody changes anything. Two domains were moved to enforce and
    /// their files verified by fetch, and the check went on saying "the policy
    /// is in testing mode, move it to enforce" for both, because the newest
    /// stored report was two days old. An operator who had just done the work
    /// was told to do it again.
    /// </para>
    /// <para>
    /// The reverse is the one that matters. A policy reverted to testing, a
    /// Pages site that went down, a custom domain that lost its binding - all
    /// would have left this cheerfully reporting enforce off historical
    /// reports. That is a memory presented as current state, which is the
    /// exact error this file refuses to make about a DNS record.
    /// </para>
    /// <para>
    /// The reported mode is kept as a second fact rather than dropped. The two
    /// disagreeing is real and temporary after a change, and saying so is more
    /// use than either half alone.
    /// </para>
    /// </remarks>
    private static void MtaStsServed(
        List<HygieneFinding> findings, PublishedRecords published, ObservedSending observed)
    {
        var served = published.ServedMtaSts;
        var reported = observed.MtaStsMode;

        // Nobody asked. Not the same as asking and failing, so the reports are
        // all there is - and the finding says that is where it came from.
        if (served is null)
        {
            if (string.Equals(reported, MtaStsMode.Testing, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new HygieneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "MTA-STS",
                    Problem = "The last reports from senders saw this policy in testing mode, where a "
                            + "connection that does not match is reported and the mail delivered anyway. "
                            + "The policy file itself was not fetched on this run, so this describes what "
                            + "senders saw rather than what is served now.",
                    Fix = "Move the policy to enforce once the reports show no failures. Run this with a "
                        + "resolver and outbound HTTPS available to judge the file that is actually served.",
                    Reference = "RFC 8461 §5",
                });
            }

            return;
        }

        // Announced and not served. Worse than never having announced it: a
        // sender that cached the old file keeps honouring it until max_age
        // expires, and nothing published afterwards reaches it.
        if (!served.Reachable || served.Policy is null)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "MTA-STS",
                Problem = $"The _mta-sts record announces a policy and the file is not being served - "
                        + $"{served.Problem ?? "it could not be read"}. Senders that have not cached one "
                        + "get no policy at all, and any that cached the last good one keep honouring it "
                        + "until it expires, whatever is changed in the meantime.",
                Fix = "Serve the policy file again at the announced host, or remove the _mta-sts record "
                    + "until it is served. Announcing a policy nobody can fetch protects nothing.",
                Reference = "RFC 8461 §3.3",
            });

            return;
        }

        var policy = served.Policy;

        if (string.Equals(policy.Mode, MtaStsMode.Testing, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "MTA-STS",
                Problem = "The policy being served is in testing mode. A sending server reports a "
                        + "connection that does not match it and delivers the mail anyway, so nothing is "
                        + "actually enforced.",
                Fix = "Move the policy to enforce once the reports show no failures.",
                Reference = "RFC 8461 §5",
            });
        }
        else if (string.Equals(policy.Mode, MtaStsMode.None, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "MTA-STS",
                Problem = "The policy being served says mode: none, which switches MTA-STS off while the "
                        + "_mta-sts record goes on announcing it. Nothing is enforced and nothing is "
                        + "reported as not enforced.",
                Fix = "Set the mode to testing or enforce, or remove the _mta-sts record. mode: none is "
                    + "for retiring a policy safely, not for leaving one in place.",
                Reference = "RFC 8461 §3.2",
            });
        }
        else if (string.Equals(reported, MtaStsMode.Testing, StringComparison.OrdinalIgnoreCase))
        {
            // The state right after a change, and the one that used to produce
            // a confident instruction to redo work already done.
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Tidy,
                Record = "MTA-STS",
                Problem = "The policy being served is in enforce mode, and the last reports from senders "
                        + "still describe testing. That is what a recent change looks like: senders act on "
                        + "the file they cached until it expires.",
                Fix = "Nothing. The reports catch up as senders re-fetch the policy.",
                Reference = "RFC 8461 §5",
            });
        }

        MtaStsCoversTheMailServers(findings, policy, published.MxHosts);
        MtaStsLastsLongEnough(findings, policy);
    }

    /// <summary>
    /// Whether the policy is cached long enough to be worth having.
    /// </summary>
    /// <remarks>
    /// <para>
    /// max_age is not a housekeeping value - it is the whole of the protection
    /// between fetches. MTA-STS is trust on first use: a sender honours the
    /// policy it holds, and an attacker who can interfere with the network can
    /// also stop the next fetch succeeding. All they have to do then is wait
    /// for the cached copy to expire, and the sender goes back to accepting
    /// whatever certificate and whichever host it is offered.
    /// </para>
    /// <para>
    /// So a one-day max_age means a one-day wait. RFC 8461 §3.2 asks for weeks
    /// for exactly this reason. A domain in enforce mode with a short max_age
    /// reads as fully protected everywhere in this product and in every other
    /// one, and is a day of patience away from not being.
    /// </para>
    /// <para>
    /// Only raised under enforce. In testing nothing is enforced whatever the
    /// max_age is, and the testing finding above already says the thing worth
    /// saying.
    /// </para>
    /// </remarks>
    private static void MtaStsLastsLongEnough(List<HygieneFinding> findings, MtaStsPolicy policy)
    {
        const int week = 604800;

        if (!string.Equals(policy.Mode, MtaStsMode.Enforce, StringComparison.OrdinalIgnoreCase)) { return; }
        if (policy.MaxAgeSeconds >= week) { return; }

        var days = Math.Max(1, policy.MaxAgeSeconds / 86400);

        findings.Add(new HygieneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "MTA-STS",
            Problem = $"The policy is enforced but expires after {Plural(days, "day")}. A sender only "
                    + "honours the copy it holds, so an attacker who can block the next fetch has to wait "
                    + $"{Plural(days, "day")} for this domain to stop being protected at all.",
            Fix = $"Raise max_age to at least 604800 (one week); 1209600 or more is the usual choice. "
                + "Lower it deliberately and briefly before changing MX records, then put it back.",
            Reference = "RFC 8461 §3.2",
        });
    }

    private static string Plural(int count, string noun) =>
        count == 1 ? $"1 {noun}" : $"{count} {noun}s";

    /// <summary>
    /// Whether the policy lists the mail servers the domain actually uses.
    /// </summary>
    /// <remarks>
    /// The check with teeth, and one nothing in this product made before. A
    /// sender that reaches a host the policy does not list, under enforce,
    /// does not deliver and does not fall back - it defers and eventually
    /// bounces. A domain whose MX moved after its policy was written is
    /// refusing its own mail, and the only signal is a TLS report, which most
    /// domains never collect.
    /// </remarks>
    private static void MtaStsCoversTheMailServers(
        List<HygieneFinding> findings, MtaStsPolicy policy, IReadOnlyList<string> mxHosts)
    {
        // Empty means the MX lookup did not answer. A domain with no mail
        // servers is not a thing, so concluding anything from an empty list
        // would be building an instruction on a failed lookup.
        if (mxHosts.Count == 0) { return; }

        var uncovered = policy.Uncovered(mxHosts);
        if (uncovered.Count == 0) { return; }

        var enforcing = string.Equals(policy.Mode, MtaStsMode.Enforce, StringComparison.OrdinalIgnoreCase);
        var hosts = string.Join(", ", uncovered);

        findings.Add(new HygieneFinding
        {
            Severity = enforcing ? HygieneSeverity.Breaking : HygieneSeverity.Weakness,
            Record = "MTA-STS",
            Problem = enforcing
                ? $"The policy is in enforce mode and does not list {hosts}, which is where this domain's "
                  + "MX records point. A sender that reaches a host the policy does not name refuses to "
                  + "deliver and does not fall back, so this is mail being bounced rather than a tidiness "
                  + "problem."
                : $"The policy does not list {hosts}, which is where this domain's MX records point. In "
                  + "testing mode that is only reported, but moving to enforce with this unchanged would "
                  + "start refusing the domain's own mail.",
            Fix = $"Add {hosts} to the policy's mx: lines, or correct them if the MX records changed after "
                + "the policy was written. Do it before advancing the mode, not after.",
            Reference = "RFC 8461 §4.1",
        });
    }

    // ---- helpers -------------------------------------------------------------

    private static int Strength(string policy) => policy.ToLowerInvariant() switch
    {
        "reject" => 3,
        "quarantine" => 2,
        "none" => 1,
        _ => 0,
    };
}
