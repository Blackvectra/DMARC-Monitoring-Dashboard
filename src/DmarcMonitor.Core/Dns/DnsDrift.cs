namespace DmarcMonitor.Core.Dns;

/// <summary>
/// The records that decide a domain's mail, as read at one moment.
/// </summary>
public sealed record DnsState
{
    public string? Spf { get; init; }

    /// <summary>
    /// How many v=spf1 records the apex published. More than one is a fault on
    /// its own: RFC 7208 section 4.5 has the receiver return permerror.
    /// </summary>
    public int SpfCount { get; init; }

    public string? Dmarc { get; init; }
    public string? MtaSts { get; init; }
    public string? TlsRpt { get; init; }
}

/// <summary>One record that changed between two readings.</summary>
/// <param name="RecordType">spf, dmarc, mta-sts or tls-rpt, as dns_drift_events stores it.</param>
/// <param name="Severity">info, warning or critical.</param>
public sealed record DriftChange(string RecordType, string? OldValue, string? NewValue, string Summary, string Severity);

/// <summary>
/// What changed in a domain's DNS between two readings, and how much it
/// matters.
/// </summary>
/// <remarks>
/// <para>
/// The point is the MSP hearing it before the client's mail does. A client
/// who drops an SPF include while changing mail platforms, or whose new
/// registrar "tidies up" the DMARC record, finds out when invoices bounce -
/// weeks later, from the reports, if at all. Compared on every scan, it is a
/// line on a screen the next morning.
/// </para>
/// <para>
/// Severity is about consequence, not size. Loosening the DMARC policy or
/// taking the report address away is critical: one lets forgeries through
/// and the other makes this product blind to the domain. Tightening it is a
/// warning, because a stricter policy is the right direction and also the one
/// that starts refusing a client's own mis-sent mail.
/// </para>
/// </remarks>
public static class DnsDrift
{
    public static IReadOnlyList<DriftChange> Compare(DnsState previous, DnsState current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        var changes = new List<DriftChange>();

        if (Differs(previous.Spf, current.Spf) || previous.SpfCount != current.SpfCount)
        {
            changes.Add(Spf(previous, current));
        }

        if (Differs(previous.Dmarc, current.Dmarc))
        {
            changes.Add(Dmarc(previous.Dmarc, current.Dmarc));
        }

        if (Differs(previous.MtaSts, current.MtaSts))
        {
            changes.Add(Simple("mta-sts", "MTA-STS", previous.MtaSts, current.MtaSts,
                removed: "warning", removedText: "MTA-STS is no longer announced, so senders stop requiring encryption."));
        }

        if (Differs(previous.TlsRpt, current.TlsRpt))
        {
            changes.Add(Simple("tls-rpt", "TLS-RPT", previous.TlsRpt, current.TlsRpt,
                removed: "warning", removedText: "TLS-RPT was removed, so failed encrypted deliveries are no longer reported."));
        }

        return changes;
    }

    private static DriftChange Spf(DnsState previous, DnsState current)
    {
        if (current.SpfCount > 1)
        {
            return new("spf", previous.Spf, current.Spf,
                $"SPF: {current.SpfCount} SPF records are now published. Receivers treat that as an error, so every "
                + "SPF check fails.", "critical");
        }

        if (current.Spf is null)
        {
            return new("spf", previous.Spf, null,
                "SPF: the record was removed. No server is authorized to send as this domain.", "critical");
        }

        if (previous.Spf is null)
        {
            return new("spf", null, current.Spf, "SPF: a record was published.", "info");
        }

        var before = SpfRecord.Parse(previous.Spf);
        var after = SpfRecord.Parse(current.Spf);

        if (!after.IsValid)
        {
            return new("spf", previous.Spf, current.Spf, $"SPF: the record no longer parses ({after.Error}).", "critical");
        }

        var oldTerms = before.Terms.Where(t => t.Name != "all").Select(t => t.Raw).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newTerms = after.Terms.Where(t => t.Name != "all").Select(t => t.Raw).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var parts = new List<string>();
        parts.AddRange(newTerms.Except(oldTerms, StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).Select(t => "+" + t));
        parts.AddRange(oldTerms.Except(newTerms, StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).Select(t => "-" + t));

        var oldAll = before.All?.Raw ?? "(no all)";
        var newAll = after.All?.Raw ?? "(no all)";
        if (!string.Equals(oldAll, newAll, StringComparison.OrdinalIgnoreCase)) { parts.Add($"{oldAll} → {newAll}"); }

        // A removed authorization is how a working sender stops working. A
        // weaker "all" lets more through. Either deserves attention; an added
        // include on its own is somebody onboarding a service.
        var removed = oldTerms.Except(newTerms, StringComparer.OrdinalIgnoreCase).Any();
        var weakerAll = Strength(newAll) < Strength(oldAll);
        var severity = removed || weakerAll ? "warning" : "info";

        var summary = parts.Count == 0
            ? "SPF: the record was rewritten with the same meaning."
            : "SPF: " + string.Join(", ", parts) + ".";

        return new("spf", previous.Spf, current.Spf, summary, severity);
    }

    private static DriftChange Dmarc(string? previousText, string? currentText)
    {
        if (currentText is null)
        {
            return new("dmarc", previousText, null,
                "DMARC: the record was removed. Receivers apply no policy, and no reports will arrive.", "critical");
        }

        if (previousText is null)
        {
            return new("dmarc", null, currentText, "DMARC: a record was published.", "info");
        }

        var before = DmarcRecord.Parse(previousText);
        var after = DmarcRecord.Parse(currentText);

        if (!after.IsValid)
        {
            return new("dmarc", previousText, currentText,
                $"DMARC: the record no longer parses ({after.Error}), so receivers ignore it.", "critical");
        }

        var parts = new List<string>();
        var severity = "info";

        void Raise(string to)
        {
            if (Rank(to) > Rank(severity)) { severity = to; }
        }

        if (!string.Equals(before.Policy, after.Policy, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"p={Show(before.Policy)} → p={Show(after.Policy)}");
            Raise(PolicyStrength(after.Policy) < PolicyStrength(before.Policy) ? "critical" : "warning");
        }

        if (!string.Equals(before.EffectiveSubdomainPolicy, after.EffectiveSubdomainPolicy, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"sp={Show(before.EffectiveSubdomainPolicy)} → sp={Show(after.EffectiveSubdomainPolicy)}");
            Raise(PolicyStrength(after.EffectiveSubdomainPolicy) < PolicyStrength(before.EffectiveSubdomainPolicy) ? "critical" : "warning");
        }

        if (before.Percent != after.Percent)
        {
            parts.Add($"pct={before.Percent} → pct={after.Percent}");
            Raise(after.Percent < before.Percent ? "warning" : "info");
        }

        if (!string.Equals(Normalize(before.Rua), Normalize(after.Rua), StringComparison.OrdinalIgnoreCase))
        {
            // The report address is how this product sees the domain at all.
            // Taken away, or pointed somewhere else, the dashboard goes quiet
            // and looks healthy while it does.
            var lost = Addresses(before.Rua).Except(Addresses(after.Rua), StringComparer.OrdinalIgnoreCase).ToList();
            parts.Add(after.Rua.Length == 0
                ? "reports (rua) removed"
                : $"rua {Show(before.Rua)} → {Show(after.Rua)}");
            Raise(lost.Count > 0 ? "critical" : "info");
        }

        if (before.StrictDkim != after.StrictDkim || before.StrictSpf != after.StrictSpf)
        {
            parts.Add($"alignment adkim={(before.StrictDkim ? "s" : "r")}/aspf={(before.StrictSpf ? "s" : "r")} → "
                    + $"adkim={(after.StrictDkim ? "s" : "r")}/aspf={(after.StrictSpf ? "s" : "r")}");
            Raise("warning");
        }

        var summary = parts.Count == 0
            ? "DMARC: the record was rewritten with the same meaning."
            : "DMARC: " + string.Join(", ", parts) + ".";

        return new("dmarc", previousText, currentText, summary, severity);
    }

    private static DriftChange Simple(
        string type, string label, string? previous, string? current, string removed, string removedText) =>
        current is null ? new(type, previous, null, $"{label}: {removedText}", removed)
        : previous is null ? new(type, null, current, $"{label}: a record was published.", "info")
        : new(type, previous, current, $"{label}: the record changed.", "info");

    private static bool Differs(string? a, string? b) =>
        !string.Equals(a?.Trim(), b?.Trim(), StringComparison.Ordinal);

    private static int Rank(string severity) => severity switch
    {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    };

    private static int PolicyStrength(string policy) => policy.ToLowerInvariant() switch
    {
        "reject" => 2,
        "quarantine" => 1,
        _ => 0,
    };

    private static int Strength(string all) => all.Length == 0 ? 0 : all[0] switch
    {
        '-' => 3,
        '~' => 2,
        '?' => 1,
        '+' => 0,
        _ => all.StartsWith("all", StringComparison.OrdinalIgnoreCase) ? 0 : 1,
    };

    private static string Show(string value) => value.Length == 0 ? "(none)" : value;

    private static string Normalize(string rua) => string.Join(",", Addresses(rua).Order(StringComparer.OrdinalIgnoreCase));

    private static IEnumerable<string> Addresses(string rua) =>
        rua.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Select(a => a.Split('!')[0].Trim());
}
