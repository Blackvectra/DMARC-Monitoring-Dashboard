using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Domains;

namespace DmarcMonitor.Core.Reporting;

/// <summary>One address a domain asks for its reports to be sent to.</summary>
/// <param name="Address">The mailbox, without the mailto: or any size limit.</param>
/// <param name="Domain">The domain that mailbox is in.</param>
/// <param name="External">
/// True when that domain is a different organization from the one reporting,
/// which is what makes an authorization record necessary.
/// </param>
public sealed record ReportDestination(string Address, string Domain, bool External)
{
    /// <summary>
    /// Where the receiving domain must publish its permission (RFC 7489 §7.1).
    /// </summary>
    public string AuthorizationName(string reportingDomain) =>
        $"{reportingDomain.Trim().TrimEnd('.').ToLowerInvariant()}._report._dmarc.{Domain}";
}

/// <summary>What is known about one domain's route back to the collector.</summary>
public sealed record DomainReachability
{
    public required string Domain { get; init; }

    /// <summary>What the domain publishes. Empty means no rua, or none readable.</summary>
    public IReadOnlyList<ReportDestination> Destinations { get; init; } = [];

    /// <summary>True when the DMARC record could not be read, so absence proves nothing.</summary>
    public bool DnsFailed { get; init; }

    /// <summary>p= as published, for saying how much the silence costs.</summary>
    public string Policy { get; init; } = "none";

    /// <summary>
    /// The TXT record found at each external destination's authorization name,
    /// keyed by that name. A null value means the lookup could not answer; a
    /// missing key means it was not looked up.
    /// </summary>
    public IReadOnlyDictionary<string, string?> Authorizations { get; init; } =
        new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Reports held for this domain, ever.</summary>
    public int ReportsHeld { get; init; }

    /// <summary>When the newest arrived, or null when none ever has.</summary>
    public DateTimeOffset? LastReport { get; init; }
}

/// <summary>
/// Whether a domain's reports can actually get back to the collector.
///
/// An MSP is the rua destination for every client, and two things break that
/// without a word being said anywhere.
///
/// The first is RFC 7489 §7.1. When a client's rua points at a mailbox in
/// somebody else's domain, that domain has to publish a record saying it will
/// accept them. A reporter that checks and finds nothing simply does not send,
/// and tells nobody. Three of sixteen real domains were broken this way and
/// the only way to find them was to diff the published names against the
/// client list by hand.
///
/// The second is a domain reporting to a mailbox nobody collects. One real
/// domain sits at p=reject with strict alignment on both mechanisms and has
/// never produced a single report here, because its rua points at a mailbox
/// the collector does not read. A domain at reject that nobody is watching is
/// the worst combination available: its failures are rejections and the
/// evidence goes somewhere nobody looks.
/// </summary>
public static class ReportReachability
{
    /// <summary>
    /// Days of silence from a domain that has reported before, after which it
    /// is worth saying so.
    /// </summary>
    /// <remarks>
    /// Receivers send daily, and the large ones send for every domain they
    /// carry mail for. A week and a half of nothing, from a domain that used
    /// to report, is not a quiet week - it is usually the rua address having
    /// been changed, or the collector having stopped.
    /// </remarks>
    public const int QuietAfterDays = 10;

    /// <summary>
    /// Every address in a rua tag, and whether each needs authorizing.
    /// </summary>
    /// <remarks>
    /// The tag is a comma-separated list and each entry may carry a size limit
    /// - <c>mailto:d@example.com!10m</c> - which is part of the URI and not
    /// part of the address. Dropping it matters: the authorization record is
    /// published under the address's domain, and "example.com!10m" is not a
    /// domain anybody can publish under.
    /// </remarks>
    public static IReadOnlyList<ReportDestination> Destinations(string? rua, string forDomain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(forDomain);

        if (string.IsNullOrWhiteSpace(rua)) { return []; }

        var from = forDomain.Trim().TrimEnd('.').ToLowerInvariant();
        var found = new List<ReportDestination>();

        foreach (var entry in rua.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var text = entry;

            // A destination that is not a mailto is one this cannot reason
            // about - an https endpoint, or a typo - and is skipped rather
            // than guessed at.
            if (!text.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) { continue; }

            text = text["mailto:".Length..].Trim();

            var bang = text.IndexOf('!', StringComparison.Ordinal);
            if (bang >= 0) { text = text[..bang].Trim(); }

            var at = text.LastIndexOf('@');
            if (at <= 0 || at == text.Length - 1) { continue; }

            var domain = text[(at + 1)..].Trim().TrimEnd('.').ToLowerInvariant();
            if (domain.Length == 0) { continue; }

            // Same organization needs no authorization: RFC 7489 §7.1 is about
            // one domain accepting reports on another's behalf.
            var external = Alignment.Classify(domain, from) == AlignmentVerdict.Unrelated;

            found.Add(new ReportDestination(text.ToLowerInvariant(), domain, external));
        }

        return found;
    }

    public static IReadOnlyList<HygieneFinding> Assess(DomainReachability domain, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(domain);

        if (domain.DnsFailed)
        {
            return
            [
                new HygieneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "reporting",
                    Problem = $"The DMARC record for {domain.Domain} could not be read, so nothing is known "
                            + "about where its reports go.",
                    Fix = "Check the domain still resolves, then run this again.",
                },
            ];
        }

        var findings = new List<HygieneFinding>();

        if (domain.Destinations.Count == 0)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "reporting",
                Problem = $"{domain.Domain} publishes no rua address, so no receiver sends aggregate "
                        + "reports about it and nothing here can ever describe its mail."
                        + Costs(domain.Policy),
                Fix = "Add rua=mailto: to the _dmarc record, pointing at the reporting mailbox.",
                Reference = "RFC 7489 §6.3",
            });

            return findings;
        }

        Authorized(findings, domain);
        Arriving(findings, domain, now);

        return [.. findings.OrderByDescending(f => f.Severity)];
    }

    /// <summary>
    /// Whether each external destination's domain has agreed to receive these.
    /// </summary>
    /// <remarks>
    /// The silent failure. A reporter that looks for the authorization record
    /// and does not find it declines to send and reports that to nobody, so
    /// what an operator sees is a customer that simply never produces any
    /// data - indistinguishable from a domain with no mail.
    /// </remarks>
    private static void Authorized(List<HygieneFinding> findings, DomainReachability domain)
    {
        foreach (var destination in domain.Destinations.Where(d => d.External))
        {
            var name = destination.AuthorizationName(domain.Domain);
            if (!domain.Authorizations.TryGetValue(name, out var record))
            {
                continue;   // not looked up; nothing may be concluded
            }

            if (record is null)
            {
                findings.Add(new HygieneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "reporting",
                    Problem = $"The authorization record at {name} could not be read, so whether "
                            + $"{destination.Domain} accepts reports for {domain.Domain} is unknown.",
                    Fix = "Run this again when the resolver is answering.",
                    Reference = "RFC 7489 §7.1",
                });

                continue;
            }

            if (ZoneAudit.IsDmarcVersion(record, exact: true)) { continue; }

            var casing = record.Length > 0 && ZoneAudit.IsDmarcVersion(record, exact: false);

            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "reporting",
                Problem = record.Length == 0
                    ? $"{domain.Domain} sends its reports to {destination.Address}, and "
                      + $"{destination.Domain} publishes nothing at {name} to say it accepts them. A "
                      + "receiver checks that record, finds nothing, and silently does not send - so this "
                      + "domain produces no reports at all and nothing says why."
                    : casing
                        ? $"The record at {name} is \"{record}\". The version has to be DMARC1 in capitals, "
                          + "so this authorizes nothing and the reports are never sent."
                        : $"The record at {name} is \"{record}\", which is not a DMARC record, so it "
                          + "authorizes nothing and the reports are never sent.",
                Fix = $"Publish a TXT record at {name} containing \"v=DMARC1\".",
                Reference = "RFC 7489 §7.1",
            });
        }
    }

    /// <summary>Whether anything has actually arrived.</summary>
    private static void Arriving(List<HygieneFinding> findings, DomainReachability domain, DateTimeOffset now)
    {
        if (domain.ReportsHeld == 0)
        {
            // Only worth saying once the authorization question is settled: a
            // domain that is not authorized already has its explanation above.
            //
            // Severity, not the citation. A lookup that could not answer also
            // cites §7.1, and blaming the silence on a missing authorization
            // when nobody could read the record is a claim on no evidence -
            // and sends the operator to publish something that may already be
            // there and correct. Only the established faults are Breaking.
            var unauthorized = findings.Exists(
                f => f.Severity == HygieneSeverity.Breaking
                     && f.Reference.StartsWith("RFC 7489 §7.1", StringComparison.Ordinal));

            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "reporting",
                Problem = $"{domain.Domain} asks for reports at "
                        + $"{string.Join(", ", domain.Destinations.Select(d => d.Address))} and not one has "
                        + "ever arrived here."
                        + (unauthorized
                            ? " The missing authorization above is the likely reason."
                            : " Either the collector does not read that mailbox, or the record was published "
                              + "too recently for the first reports to arrive - receivers send daily.")
                        + Costs(domain.Policy),
                Fix = unauthorized
                    ? "Publish the authorization record, then give it a day."
                    : "Point the collector at that mailbox, or change the rua address to one it reads.",
                Reference = "RFC 7489 §6.3",
            });

            return;
        }

        if (domain.LastReport is not { } last) { return; }

        var silent = (int)(now - last).TotalDays;
        if (silent < QuietAfterDays) { return; }

        findings.Add(new HygieneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "reporting",
            Problem = $"{domain.Domain} has reported before - {domain.ReportsHeld} report(s) held - and "
                    + $"nothing has arrived for {silent} days. Receivers send daily, so this is usually the "
                    + "rua address having changed or the collector having stopped rather than a quiet "
                    + "period."
                    + Costs(domain.Policy),
            Fix = "Check the rua address still points at the collected mailbox, and that the collector is "
                + "running.",
            Reference = "RFC 7489 §6.3",
        });
    }

    /// <summary>
    /// What the silence costs, which depends entirely on the policy.
    /// </summary>
    /// <remarks>
    /// A domain at p=none that nobody reports on is a monitoring gap. The same
    /// domain at p=reject is refusing mail with nobody watching which mail, and
    /// the two should not read the same.
    /// </remarks>
    private static string Costs(string policy) => policy.ToLowerInvariant() switch
    {
        "reject" => " It is at p=reject, so its failures are refusals - mail is being lost and there is no "
                  + "record here of whose.",
        "quarantine" => " It is at p=quarantine, so its failures are going to junk with nothing here to say "
                      + "whose.",
        _ => "",
    };
}
