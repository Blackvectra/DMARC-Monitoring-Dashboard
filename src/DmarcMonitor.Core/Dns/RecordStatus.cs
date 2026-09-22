using System.Globalization;

namespace DmarcMonitor.Core.Dns;

/// <summary>What a one-glance record indicator is allowed to say.</summary>
public enum RecordState
{
    /// <summary>
    /// Nobody has looked, or nothing has been observed that would answer the
    /// question. Never a cross.
    /// </summary>
    Unknown,

    /// <summary>Published, and there is nothing wrong with it.</summary>
    Ok,

    /// <summary>Published, and something about it is wrong.</summary>
    Weak,

    /// <summary>Really absent: the resolver answered, and there was no record.</summary>
    Missing,

    /// <summary>
    /// The last lookup failed, so whatever is shown is a memory and the
    /// current state is unknown.
    /// </summary>
    Unreadable,
}

/// <summary>One record indicator: what it is, how it is, and why.</summary>
/// <param name="Label">SPF, DKIM, DMARC, MTA-STS or TLS-RPT.</param>
/// <param name="State">What to draw.</param>
/// <param name="Detail">A full sentence, for the title attribute and for anybody asking why.</param>
/// <param name="AsOf">When the reading behind this was taken, or null when there is none.</param>
/// <param name="Stale">True when that reading is old enough that it should not be trusted as current.</param>
public sealed record RecordChip(
    string Label, RecordState State, string Detail, DateTimeOffset? AsOf = null, bool Stale = false)
{
    /// <summary>The class carrying its color. One word, so the stylesheet stays greppable.</summary>
    public string Css => State switch
    {
        RecordState.Ok => "ok",
        RecordState.Weak => "weak",
        RecordState.Missing => "missing",
        RecordState.Unreadable => "unreadable",
        _ => "unknown",
    };

    /// <summary>
    /// The character drawn inside the chip.
    /// </summary>
    /// <remarks>
    /// A shape as well as a color, because roughly one man in twelve cannot
    /// tell the red one from the green one, and a table of eighty rows where
    /// the only difference is hue is a table that person cannot read.
    /// </remarks>
    public string Glyph => State switch
    {
        RecordState.Ok => "✓",          // check mark
        RecordState.Weak => "!",
        RecordState.Missing => "✗",     // ballot X
        RecordState.Unreadable => "?",
        _ => "–",                       // en dash: nothing has been established
    };

    /// <summary>The detail with the reading's age appended, which is the whole sentence to show.</summary>
    public string Title => AsOf is null
        ? Detail
        : $"{Detail} Last read {Age(AsOf.Value)}.";

    private static string Age(DateTimeOffset when)
    {
        var days = (int)(DateTimeOffset.UtcNow - when).TotalDays;
        return days switch
        {
            <= 0 => "today",
            1 => "yesterday",
            _ => $"{days.ToString(CultureInfo.InvariantCulture)} days ago",
        };
    }
}

/// <summary>
/// Turns a stored DNS reading into the indicators on the domains table.
///
/// Pure, and separate from the reading for the same reason DnsHygiene is
/// separate from DnsLookup: every combination can then be tested without a
/// resolver, and the rule that matters most here is a rule about what must
/// NOT be said. A cross means "the resolver answered and there was no
/// record". It must never mean "the lookup timed out", never mean "nobody has
/// looked yet", and never mean "we looked in March". Each of those is a
/// different indicator, because each of them leads somewhere different: one
/// is a fault to fix, one is a network problem, one is a job that is not
/// running, and one is a number nobody should act on.
///
/// This answers a narrower question than DnsHygiene, from a narrower input -
/// a stored snapshot rather than a live reading - so it does not call into
/// it. Feeding DnsHygiene a PublishedRecords rebuilt from stored columns
/// would have it judge fields the snapshot does not hold, and report
/// confidently on include chains it never saw.
/// </summary>
public static class RecordStatus
{
    /// <summary>
    /// After how long a successful reading stops counting as current.
    /// </summary>
    /// <remarks>
    /// A week, against a scan that runs daily: long enough that one missed
    /// night is not an alarm, short enough that a scan which quietly stopped
    /// a fortnight ago is visible before anybody makes a decision on it.
    /// </remarks>
    public const int StaleAfterDays = 7;

    /// <summary>
    /// Every indicator for one domain, in reading order.
    /// </summary>
    /// <remarks>
    /// Authentication first - SPF, DKIM, DMARC, which between them say whether
    /// a message was really from the domain - then transport, MTA-STS and
    /// TLS-RPT, which say whether it crossed the internet where nobody could
    /// read it. They are different questions and a domain can be perfect at
    /// one and absent at the other: p=reject with flawless alignment still
    /// hands every message to a receiver in plaintext if nothing requires TLS.
    /// </remarks>
    public static IReadOnlyList<RecordChip> For(
        DomainDns dns, int staleAfterDays = StaleAfterDays) =>
    [
        Spf(dns, staleAfterDays),
        Dkim(dns, staleAfterDays),
        Dmarc(dns, staleAfterDays),
        MtaSts(dns, staleAfterDays),
        TlsRpt(dns, staleAfterDays),
    ];

    public static RecordChip Dmarc(DomainDns dns, int staleAfterDays = StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(dns);

        if (Unresolved(dns, "DMARC", staleAfterDays) is { } answer) { return answer; }

        var stale = IsStale(dns, staleAfterDays);

        if (dns.DmarcRecord is null)
        {
            return new RecordChip("DMARC", RecordState.Missing,
                $"No DMARC record at _dmarc.{dns.Domain}. No policy applies and no reports are sent.",
                dns.CheckedAt, stale);
        }

        var record = DmarcRecord.Parse(dns.DmarcRecord);

        if (!record.IsValid)
        {
            return new RecordChip("DMARC", RecordState.Weak,
                $"There is a record at _dmarc.{dns.Domain}, but it is not usable DMARC: {record.Error}. "
                + "Receivers ignore it, so the domain is unprotected.",
                dns.CheckedAt, stale);
        }

        if (record.Rua.Length == 0)
        {
            return new RecordChip("DMARC", RecordState.Weak,
                $"p={record.Policy}, but no rua= address, so nobody is sent the reports "
                + "and nothing here can see what the domain is doing.",
                dns.CheckedAt, stale);
        }

        // p=none is not a fault of the record. It is a stage, the row already
        // shows it in the policy column, and the triage pip already ranks how
        // long the domain has been sitting at it. Marking it here as well
        // would be the same warning three times in one row.
        return new RecordChip("DMARC", RecordState.Ok,
            $"p={record.Policy}"
            + (record.Percent < 100 ? $" on {record.Percent}% of mail" : "")
            + $", reports to {record.Rua}.",
            dns.CheckedAt, stale);
    }

    public static RecordChip Spf(DomainDns dns, int staleAfterDays = StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(dns);

        if (Unresolved(dns, "SPF", staleAfterDays) is { } answer) { return answer; }

        var stale = IsStale(dns, staleAfterDays);

        if (dns.SpfRecordCount == 0)
        {
            return new RecordChip("SPF", RecordState.Missing,
                $"No TXT record beginning v=spf1 at {dns.Domain}. Nothing says which servers may send as it.",
                dns.CheckedAt, stale);
        }

        if (dns.SpfRecordCount > 1)
        {
            return new RecordChip("SPF", RecordState.Weak,
                $"{dns.SpfRecordCount} records beginning v=spf1 at the apex. RFC 7208 section 4.5 makes that "
                + "a permerror, so every SPF check fails however correct either record is.",
                dns.CheckedAt, stale);
        }

        if (dns.SpfLookups > DnsHygiene.SpfLookupLimit)
        {
            return new RecordChip("SPF", RecordState.Weak,
                $"Evaluating this record costs {dns.SpfLookups} DNS lookups and the limit is "
                + $"{DnsHygiene.SpfLookupLimit}, over which every check returns permerror.",
                dns.CheckedAt, stale);
        }

        // An absent all mechanism is not neutral about anything: RFC 7208
        // section 4.7 defaults it to ?all, which authorizes nobody and
        // forbids nobody, so the record ends up doing no work at all.
        if (dns.SpfAll.Length == 0)
        {
            return new RecordChip("SPF", RecordState.Weak,
                "The record has no all mechanism, so it defaults to ?all and neither authorizes "
                + "nor rejects anything.",
                dns.CheckedAt, stale);
        }

        var all = dns.SpfAll.Trim();

        if (all.StartsWith('+') || all.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            return new RecordChip("SPF", RecordState.Weak,
                "The record ends +all, which authorizes every server on the internet to send as this domain.",
                dns.CheckedAt, stale);
        }

        if (all.StartsWith('?'))
        {
            return new RecordChip("SPF", RecordState.Weak,
                "The record ends ?all, which takes no position on anything not listed, so it "
                + "protects nothing.",
                dns.CheckedAt, stale);
        }

        return new RecordChip("SPF", RecordState.Ok,
            $"One record ending {all}"
            + (dns.SpfLookups is { } n ? $", costing {n} of {DnsHygiene.SpfLookupLimit} DNS lookups" : "")
            + ".",
            dns.CheckedAt, stale);
    }

    /// <summary>
    /// The DKIM indicator, which is built from the reports rather than from a
    /// query for a record.
    /// </summary>
    /// <remarks>
    /// There is no such thing as reading "the DKIM record" for a domain. Keys
    /// live under selector names, DNS has no way to list them, and a domain
    /// with fifty selectors looks exactly like a domain with none. What can be
    /// established is which selectors have actually signed mail - the reports
    /// name them - and whether those still resolve today. So a domain nothing
    /// has been seen signing for is Unknown, not Missing: it may be signing
    /// everything perfectly and simply have sent nothing this month.
    /// </remarks>
    public static RecordChip Dkim(DomainDns dns, int staleAfterDays = StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(dns);

        if (Unresolved(dns, "DKIM", staleAfterDays) is { } answer) { return answer; }

        var stale = IsStale(dns, staleAfterDays);
        var seen = dns.DkimSelectors;

        if (seen.Count == 0)
        {
            return new RecordChip("DKIM", RecordState.Unknown,
                "No DKIM signature has been seen in any report for this domain, so there is no "
                + "selector to look up. DNS cannot be asked which selectors a domain has.",
                dns.CheckedAt, stale);
        }

        var usable = seen.Where(s => s.Usable).ToList();
        var revoked = seen.Where(s => s.Status == "revoked").ToList();
        var broken = seen.Where(s => !s.Usable && s.Status != "revoked").ToList();

        if (usable.Count == 0)
        {
            // Every selector the reports named has stopped resolving. That is
            // mail being signed with keys nobody can fetch, which fails DKIM
            // at every receiver, and it is the single most valuable thing this
            // indicator can catch.
            return new RecordChip("DKIM", RecordState.Missing,
                $"{Selectors(seen.Count)} seen signing for this domain, and none of them resolves to a "
                + $"usable key now ({Names(seen)}). Mail signed with them fails DKIM everywhere.",
                dns.CheckedAt, stale);
        }

        if (broken.Count > 0)
        {
            return new RecordChip("DKIM", RecordState.Weak,
                $"{usable.Count} of {seen.Count} selectors resolve. {Names(broken)} does not, and mail "
                + "signed with it fails DKIM.",
                dns.CheckedAt, stale);
        }

        if (revoked.Count > 0)
        {
            return new RecordChip("DKIM", RecordState.Weak,
                $"{Names(revoked)} is published as revoked (p= with nothing after it) but is still "
                + "signing mail, which fails DKIM.",
                dns.CheckedAt, stale);
        }

        var weak = usable.Where(s => s.Status == "weak").ToList();
        if (weak.Count > 0)
        {
            return new RecordChip("DKIM", RecordState.Weak,
                $"{Names(weak)} publishes a key under 1024 bits, which large receivers have refused "
                + "since 2018. Rotate to 2048.",
                dns.CheckedAt, stale);
        }

        var bits = usable.Where(s => s.Bits is > 0).Select(s => s.Bits!.Value).DefaultIfEmpty(0).Min();

        return new RecordChip("DKIM", RecordState.Ok,
            $"{Selectors(usable.Count)} resolving to a key ({Names(usable)})"
            + (bits > 0 ? $", smallest {bits} bits" : "") + ".",
            dns.CheckedAt, stale);
    }

    /// <summary>
    /// The MTA-STS indicator, which is about a file rather than a record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The only one of these where DNS does not hold the answer. The TXT
    /// record at _mta-sts announces a policy id and nothing else; the mode -
    /// the part that decides whether anything is required of senders - lives
    /// in a file served over HTTPS at mta-sts.&lt;domain&gt;. So there are two
    /// halves and both can be wrong independently, which is why a record
    /// present and a policy served are drawn as different states.
    /// </para>
    /// <para>
    /// A policy in <c>testing</c> is the trap this chip exists to catch. Its
    /// failures are reported and its mail is delivered over plaintext anyway,
    /// so a domain can sit in it for years producing perfectly clean reports
    /// while being no better protected than one with no policy at all. Drawing
    /// a tick for that would be the product telling somebody they were safe.
    /// </para>
    /// </remarks>
    public static RecordChip MtaSts(DomainDns dns, int staleAfterDays = StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(dns);

        if (Unresolved(dns, "MTA-STS", staleAfterDays) is { } answer) { return answer; }

        var stale = IsStale(dns, staleAfterDays);

        if (string.IsNullOrWhiteSpace(dns.MtaStsRecord))
        {
            return new RecordChip("MTA-STS", RecordState.Missing,
                $"No TXT record at _mta-sts.{dns.Domain}. Nothing requires a sender to use TLS, so a "
                + "network in the middle can strip encryption and read the mail in plain text.",
                dns.CheckedAt, stale);
        }

        // The record is there and nobody has fetched the file. That is not a
        // fault and must not be drawn as one: the mode is simply not in DNS,
        // and a reading taken by something that does not make HTTPS requests
        // never knew it.
        if (dns.MtaStsMode.Length == 0)
        {
            return new RecordChip("MTA-STS", RecordState.Unknown,
                $"A policy is announced at _mta-sts.{dns.Domain}, but the file at mta-sts.{dns.Domain} has "
                + "not been fetched, so what mode it is in is unknown. Run: dmarc check "
                + $"{dns.Domain} --save",
                dns.CheckedAt, stale);
        }

        return dns.MtaStsMode.ToLowerInvariant() switch
        {
            MtaStsMode.Enforce => new RecordChip("MTA-STS", RecordState.Ok,
                "The policy being served is in enforce: a sender that supports MTA-STS will refuse to "
                + "deliver rather than hand the mail over a connection it cannot trust.",
                dns.CheckedAt, stale),

            MtaStsMode.Testing => new RecordChip("MTA-STS", RecordState.Weak,
                "The policy being served is in testing, which enforces nothing. Failures are reported "
                + "and the mail is delivered over plain text anyway, so clean reports here are the "
                + "signal to move to enforce rather than evidence of being protected.",
                dns.CheckedAt, stale),

            MtaStsMode.None => new RecordChip("MTA-STS", RecordState.Weak,
                "The policy being served is mode=none, which is a policy switched off - the way one is "
                + "retired without stranding senders that cached it. Nothing is required of anybody.",
                dns.CheckedAt, stale),

            // Announced and not served. Worse than not announcing at all, in
            // the sense that it is a job somebody started and stopped: the
            // record says a policy exists and no sender can fetch it, so none
            // of them applies it.
            _ => new RecordChip("MTA-STS", RecordState.Weak,
                $"A policy is announced at _mta-sts.{dns.Domain} and the file could not be fetched from "
                + $"mta-sts.{dns.Domain}. Senders ignore a policy they cannot fetch, so this protects "
                + "nothing. Run: dmarc mta-sts check " + dns.Domain,
                dns.CheckedAt, stale),
        };
    }

    /// <summary>
    /// The TLS-RPT indicator: whether anybody is being asked to report how
    /// delivery to this domain went.
    /// </summary>
    /// <remarks>
    /// The cheapest record on this list and the one to publish first. It
    /// changes nothing about delivery - it only asks receivers to say what
    /// happened - and without it MTA-STS is enforcement with the lights off:
    /// a policy that starts refusing mail, and no way to find out that it has.
    /// </remarks>
    public static RecordChip TlsRpt(DomainDns dns, int staleAfterDays = StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(dns);

        if (Unresolved(dns, "TLS-RPT", staleAfterDays) is { } answer) { return answer; }

        var stale = IsStale(dns, staleAfterDays);

        if (string.IsNullOrWhiteSpace(dns.TlsRptRecord))
        {
            return new RecordChip("TLS-RPT", RecordState.Missing,
                $"No TXT record at _smtp._tls.{dns.Domain}. Nobody is asked to report how delivery went, "
                + "so mail failing to connect securely is invisible.",
                dns.CheckedAt, stale);
        }

        var rua = Rua(dns.TlsRptRecord);

        if (rua.Length == 0)
        {
            return new RecordChip("TLS-RPT", RecordState.Weak,
                $"There is a record at _smtp._tls.{dns.Domain} with no rua= address, so it names nowhere "
                + "to send the reports to and no receiver will send any.",
                dns.CheckedAt, stale);
        }

        // Where the reports go is stated rather than judged. An address
        // belonging to another provider is a perfectly deliberate arrangement,
        // and it does mean this product will never see those reports - which
        // is worth reading off the row rather than discovering after a week of
        // wondering why the TLS reports page is empty.
        return new RecordChip("TLS-RPT", RecordState.Ok,
            $"Receivers are asked to report delivery failures to {rua}.",
            dns.CheckedAt, stale);
    }

    /// <summary>
    /// The rua= value of a TLS-RPT record, or empty when it names none.
    /// </summary>
    /// <remarks>
    /// Deliberately small. RFC 8460 §3 allows a comma-separated list of
    /// mailto: and https: endpoints, and reproducing the whole grammar here to
    /// fill a tooltip would be a second parser free to disagree with the one
    /// that matters. What is needed is whether an address is named and what it
    /// is, so the first value is taken and the rest counted.
    /// </remarks>
    private static string Rua(string record)
    {
        foreach (var field in record.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!field.StartsWith("rua=", StringComparison.OrdinalIgnoreCase)) { continue; }

            var endpoints = field[4..]
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if (endpoints.Length == 0) { return ""; }

            var first = endpoints[0];
            if (first.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) { first = first[7..]; }

            return endpoints.Length > 1
                ? $"{first} and {(endpoints.Length - 1).ToString(CultureInfo.InvariantCulture)} more"
                : first;
        }

        return "";
    }

    /// <summary>
    /// The answer when the question cannot be asked of the records at all,
    /// or null when it can.
    /// </summary>
    /// <remarks>
    /// The three cases this exists for are the three a chip most easily gets
    /// wrong, and all three would otherwise be drawn as a cross: nobody has
    /// looked, the look failed, and there is no such domain. Only the last of
    /// those is really an absence, and even it means something quite different
    /// from a missing record - there is no zone to publish into, so the fix is
    /// a typo, not a DNS edit.
    /// </remarks>
    private static RecordChip? Unresolved(DomainDns dns, string label, int staleAfterDays)
    {
        if (dns.Status == DnsCheckStatus.NeverChecked || dns.CheckedAt is null)
        {
            return new RecordChip(label, RecordState.Unknown,
                $"The DNS for {dns.Domain} has not been read yet, so nothing is known about its "
                + $"{label} record. Run: dmarc check --all --save");
        }

        if (dns.Status == DnsCheckStatus.Failed)
        {
            return new RecordChip(label, RecordState.Unreadable,
                $"The last attempt to read the DNS for {dns.Domain} failed, so what it publishes now "
                + $"is unknown. This is not the same as having no {label} record.",
                dns.CheckedAt, IsStale(dns, staleAfterDays));
        }

        if (dns.Status == DnsCheckStatus.NoSuchDomain)
        {
            return new RecordChip(label, RecordState.Missing,
                $"There is no domain called {dns.Domain} - the resolver says the name does not exist - "
                + "so there is no zone to publish anything into. Usually a typo.",
                dns.CheckedAt, IsStale(dns, staleAfterDays));
        }

        // Status is Ok, but no snapshot was stored against it. That should not
        // happen and is reported as not knowing rather than as an absence.
        return dns.HasReading
            ? null
            : new RecordChip(label, RecordState.Unknown,
                $"The last check of {dns.Domain} recorded no reading, so nothing can be said about "
                + $"its {label} record.",
                dns.CheckedAt, IsStale(dns, staleAfterDays));
    }

    private static bool IsStale(DomainDns dns, int staleAfterDays) =>
        dns.CheckedAt is { } when && (DateTimeOffset.UtcNow - when).TotalDays > staleAfterDays;

    private static string Selectors(int count) =>
        count == 1 ? "1 selector" : $"{count.ToString(CultureInfo.InvariantCulture)} selectors";

    /// <summary>
    /// Names the selectors rather than only counting them, capped so one
    /// domain's forty selectors do not become a paragraph.
    /// </summary>
    private static string Names(IReadOnlyList<ObservedSelector> selectors)
    {
        var shown = selectors.Take(3).Select(s => s.Selector);
        return selectors.Count > 3
            ? string.Join(", ", shown) + $" and {selectors.Count - 3} more"
            : string.Join(", ", shown);
    }
}
