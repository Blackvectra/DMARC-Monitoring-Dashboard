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
/// <param name="Label">SPF, DKIM or DMARC.</param>
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
/// Turns a stored DNS reading into the three indicators on the domains table.
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

    /// <summary>All three indicators for one domain, in reading order.</summary>
    public static IReadOnlyList<RecordChip> For(
        DomainDns dns, int staleAfterDays = StaleAfterDays) =>
        [Spf(dns, staleAfterDays), Dkim(dns, staleAfterDays), Dmarc(dns, staleAfterDays)];

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
