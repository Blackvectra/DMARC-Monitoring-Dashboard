using System.Globalization;
using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Reporting;

/// <summary>The window a report covers, and the one it is compared against.</summary>
public sealed record ReportPeriod
{
    public required DateTimeOffset Start { get; init; }
    public required DateTimeOffset End { get; init; }
    public required DateTimeOffset PreviousStart { get; init; }
    public required DateTimeOffset PreviousEnd { get; init; }
    public required string Label { get; init; }
    public required string PreviousLabel { get; init; }

    /// <summary>
    /// The calendar month that has ENDED, compared against the month before.
    /// </summary>
    /// <remarks>
    /// Calendar months rather than a rolling thirty days, because a client
    /// reconciles this against an invoice and both have to mean the same
    /// thing. Running on 3 March reports February against January, and running
    /// again on the 20th reports exactly the same period.
    /// </remarks>
    public static ReportPeriod MonthEnding(DateTimeOffset asOf)
    {
        var firstOfThisMonth = new DateTimeOffset(asOf.Year, asOf.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var start = firstOfThisMonth.AddMonths(-1);
        var end = firstOfThisMonth.AddSeconds(-1);
        var prevStart = start.AddMonths(-1);
        var prevEnd = start.AddSeconds(-1);

        return new ReportPeriod
        {
            Start = start,
            End = end,
            PreviousStart = prevStart,
            PreviousEnd = prevEnd,
            Label = start.ToString("MMMM yyyy", CultureInfo.InvariantCulture),
            PreviousLabel = prevStart.ToString("MMMM yyyy", CultureInfo.InvariantCulture),
        };
    }

    /// <summary>An explicit month, for regenerating an older report.</summary>
    public static ReportPeriod ForMonth(int year, int month) =>
        MonthEnding(new DateTimeOffset(year, month, 1, 0, 0, 0, TimeSpan.Zero).AddMonths(1));
}

/// <summary>A source seen sending as one of the client's domains.</summary>
public sealed record ReportSource
{
    public required string SourceIp { get; init; }
    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }

    /// <summary>
    /// What the address reverses to, or empty when it has no name.
    /// </summary>
    /// <remarks>
    /// The Sources page names these and the report did not, so a client was
    /// handed a row of digits and asked whether they recognised it. Nobody
    /// recognises an address; they recognise "a Comcast connection in Denver"
    /// or "one of our own servers".
    ///
    /// Read for display and never for judgement. A PTR is written by whoever
    /// holds the address, so it identifies a sender the way a return address
    /// on an envelope does - enough to recognise a provider, nowhere near
    /// enough to trust one. Nothing here feeds whether a source counts as
    /// impersonating.
    /// </remarks>
    public string ReverseName { get; init; } = "";

    /// <summary>The name if there is one, otherwise the address.</summary>
    public string Display => ReverseName.Length > 0 ? ReverseName : SourceIp;

    /// <summary>True when there is a name worth printing beside the address.</summary>
    public bool IsNamed => ReverseName.Length > 0;

    /// <summary>The domain this source authenticated for, when it authenticated at all.</summary>
    public string AuthenticatedFor { get; init; } = "";

    public IReadOnlyList<string> Domains { get; init; } = [];

    /// <summary>Other clients this same source was seen failing against.</summary>
    public int OtherClientsAffected { get; init; }

    public bool Authenticated => !string.IsNullOrEmpty(AuthenticatedFor);
    public bool IsClean => Failing == 0;

    /// <summary>Messages whose SPF check passed, for whatever domain.</summary>
    public long SpfPass { get; init; }

    /// <summary>Messages whose DKIM signature verified, for whatever domain.</summary>
    public long DkimPass { get; init; }

    /// <summary>Failing messages where SPF passed but for the wrong domain.</summary>
    public long FailedSpfNotAligned { get; init; }

    /// <summary>Failing messages where DKIM verified but for the wrong domain.</summary>
    public long FailedDkimNotAligned { get; init; }

    /// <summary>Failing messages where neither check passed at all.</summary>
    public long FailedBoth { get; init; }

    /// <summary>
    /// True when this source was seen in the previous period and not in this
    /// one.
    /// </summary>
    /// <remarks>
    /// A sender that has stopped is not a finding, but it is an inventory
    /// question: either a vendor was retired and nobody removed it from SPF,
    /// or something broke quietly. Both are worth a line.
    /// </remarks>
    public bool Retired { get; init; }
}

/// <summary>
/// What a source is, for the inventory a client is asked to confirm.
/// </summary>
/// <remarks>
/// The classification is the product. A list of addresses and percentages is
/// data; "these four are yours and correct, this one is yours and broken,
/// these two nobody can account for" is the thing somebody can act on, and it
/// is what separates this from a report parser.
///
/// Every boundary here is drawn to avoid one specific wrong accusation:
/// passing even once for the domain means the source is the client's own mail
/// path, because that is the thing a forger cannot do.
/// </remarks>
public enum SenderClass
{
    /// <summary>Known, authenticating, aligned. Nothing to do.</summary>
    Approved,

    /// <summary>The client's own path, or a recognised service, losing some of its mail.</summary>
    Misconfigured,

    /// <summary>Never authenticated, but operated by somebody the catalog recognises.</summary>
    Unidentified,

    /// <summary>Never authenticated, and nothing recognises the operator.</summary>
    Suspicious,

    /// <summary>Sent in the previous period and not in this one.</summary>
    Retired,
}

/// <summary>
/// One thing to do, with who it is for and what finishing it looks like.
/// </summary>
/// <remarks>
/// A report that ends in "consider moving to p=reject" ends in nothing. Each
/// of these names the finding, what it costs the business, the exact change,
/// and the evidence that would close it - which is what turns a document into
/// a ticket.
/// </remarks>
public sealed record RemediationItem
{
    public required string Priority { get; init; }
    public required string Finding { get; init; }
    public required string Impact { get; init; }
    public required string Action { get; init; }

    /// <summary>Who this belongs to: the provider, the customer, or a named vendor.</summary>
    public required string Owner { get; init; }

    /// <summary>What proves it is done.</summary>
    public required string Validation { get; init; }

    /// <summary>Sorts Critical first, and keeps two items of one priority in the order found.</summary>
    public int Rank => Priority switch
    {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    };
}

/// <summary>
/// Clean sources gathered under one service, for the report's "what sends
/// mail as you" list.
/// </summary>
/// <param name="Name">The service, or the address itself when it is not one we recognize.</param>
/// <param name="IsService">
/// True when <paramref name="Name"/> names a service rather than repeating an
/// address, so the report can say "17 addresses" for the one and nothing for
/// the other.
/// </param>
public sealed record ReportSender
{
    public required string Name { get; init; }
    public bool IsService { get; init; }
    public int Addresses { get; init; }
    public long Messages { get; init; }
    public IReadOnlyList<string> Domains { get; init; } = [];

    /// <summary>
    /// The address behind the name, when the row is one address rather than a
    /// service's fleet of them.
    /// </summary>
    /// <remarks>
    /// A service row gathers dozens of addresses and naming one of them would
    /// be arbitrary. A single unrecognised sender has exactly one, and the
    /// client cannot ask their hosting provider about a reverse name.
    /// </remarks>
    public string SourceIp { get; init; } = "";

    /// <summary>True when <see cref="Name"/> is something other than the address itself.</summary>
    public bool IsNamed =>
        SourceIp.Length > 0 && !Name.Equals(SourceIp, StringComparison.Ordinal);
}

/// <summary>A DNS change actually made for this client during the period.</summary>
public sealed record ReportChange
{
    public required string RecordName { get; init; }
    public required string RecordType { get; init; }
    public string PreviousValue { get; init; } = "";
    public string NewValue { get; init; } = "";
    public string Reason { get; init; } = "";
    public DateTimeOffset AppliedAt { get; init; }
    public bool WasRolledBack { get; init; }
}

/// <summary>The state of a domain's published records.</summary>
public sealed record ReportDomainHealth
{
    public required string Domain { get; init; }

    /// <summary>
    /// False when no report reached us at or before this period.
    /// </summary>
    /// <remarks>
    /// Distinct from p=none. One says the domain was published without
    /// protection, the other says nobody told us either way, and printing the
    /// first when the second is true puts a claim in a customer's report that
    /// nothing supports.
    /// </remarks>
    public bool PolicyKnown { get; init; } = true;

    public string Policy { get; init; } = "none";
    public string SubdomainPolicy { get; init; } = "";
    public int Pct { get; init; } = 100;
    public bool StrictAlignment { get; init; }
    public string MtaStsMode { get; init; } = "";
    public long Messages { get; init; }
    public long Passing { get; init; }

    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);
    public bool IsEnforcing => Policy is "reject" or "quarantine";

    public long Failing => Messages - Passing;

    /// <summary>
    /// True when enough of this domain's own mail is failing to be worth
    /// saying out loud.
    /// </summary>
    /// <remarks>
    /// Judged per domain, never against the estate's average - which is the
    /// whole point. See <see cref="ClientReport.StrugglingDomains"/>.
    /// </remarks>
    public bool IsStruggling => Messages > 0 && PassRate < ClientReport.HealthyPassRate;

    /// <summary>
    /// Whether this domain's policy could safely be raised.
    /// </summary>
    /// <remarks>
    /// The question every one of these reports is really asked, and the one
    /// most tools answer with a percentage and leave to the reader. Three
    /// states, because "ready" and "not ready" hides the common case: a domain
    /// whose own mail is fine and which is already enforcing has nothing left
    /// to decide, a domain at 99% is a decision about a known remainder, and a
    /// domain losing real mail must not be raised at all.
    ///
    /// Read against this domain's own mail, never the estate's. See
    /// <see cref="ClientReport.StrugglingDomains"/>.
    /// </remarks>
    public string Readiness =>
        Messages == 0 ? "No mail seen"
        : IsStruggling ? "Not ready"
        : IsEnforcing ? "Enforcing"
        : PassRate >= 99 ? "Ready"
        : "Conditional";

    /// <summary>The sentence under the readiness word, naming what decides it.</summary>
    public string ReadinessReason =>
        Messages == 0
            ? "Nothing was reported for this domain, so nothing can be judged."
        : IsStruggling
            ? $"{Failing:N0} of this domain's own message(s) are failing. Raising the policy would stop them."
        : IsEnforcing
            ? "Already enforcing, and its own mail is arriving."
        : PassRate >= 99
            ? "Its own mail authenticates. The policy can be raised."
            : $"{Failing:N0} message(s) would be affected by enforcement. Worth naming them before the change.";
}

/// <summary>
/// Everything one client's monthly report says.
///
/// Assembled as data first and rendered separately, so the same report can go
/// to HTML now and to PDF or a web page later without the wording being
/// rewritten, and so every figure in it can be tested.
/// </summary>
public sealed record ClientReport
{
    /// <summary>
    /// Below this, enough of a domain's mail is failing to be worth a client's
    /// attention.
    /// </summary>
    /// <remarks>
    /// Applied to each domain rather than to the estate, and that is the
    /// difference between this report and the competitors' - one of whose
    /// PDFs, measured against its own CSV, announced "100% DMARC Compliance"
    /// and "0 Total Issues" for a domain where 55 of 496 messages aligned
    /// with neither SPF nor DKIM and 51 were quarantined. A true rate of
    /// 88.9%, rounded up to perfect.
    ///
    /// The same arithmetic does it here without anybody intending to. A
    /// client with three domains at 100%, 100% and 45% averages 96.6%, which
    /// clears any estate-wide threshold - while more than half of one
    /// domain's mail is not arriving.
    /// </remarks>
    public const double HealthyPassRate = 95;

    /// <summary>
    /// What a report says instead of a provider's name when nobody has set
    /// one.
    /// </summary>
    /// <remarks>
    /// A constant rather than a literal in three files, because it is what
    /// "has this been configured" is decided by - and two of those literals
    /// had already drifted apart in capitalisation, so the check would have
    /// been asking about a string that never appears.
    ///
    /// Reads correctly mid-sentence, which is how it got shipped: "your IT
    /// provider is correcting this" is a fine sentence. It is only wrong on
    /// the cover of a document a customer is paying for.
    /// </remarks>
    public const string UnnamedProvider = "your IT provider";

    public required string ClientName { get; init; }
    public required string ProviderName { get; init; }

    /// <summary>
    /// True when this report would go out signed by nobody in particular.
    /// </summary>
    /// <remarks>
    /// Asked of the finished report rather than of configuration, because the
    /// two can disagree: an organization with its own name on the Configuration
    /// page produces correctly signed reports on an install whose
    /// <c>Reporting:ProviderName</c> is blank, and refusing those would be
    /// refusing a document that is perfectly fine.
    /// </remarks>
    public bool ProviderIsUnnamed =>
        ProviderName.Length == 0
        || ProviderName.Equals(UnnamedProvider, StringComparison.OrdinalIgnoreCase);
    public required ReportPeriod Period { get; init; }

    /// <summary>The organization's accent color, #rrggbb, or null for the default.</summary>
    public string? BrandColor { get; init; }

    /// <summary>The organization's logo as a data: URL, or null for none.</summary>
    public string? BrandLogo { get; init; }

    /// <summary>Who to contact, printed in the footer. Null for none.</summary>
    public string? ContactBlock { get; init; }
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    public IReadOnlyList<ReportDomainHealth> Domains { get; init; } = [];
    public IReadOnlyList<ReportSource> Sources { get; init; } = [];
    public IReadOnlyList<ReportChange> Changes { get; init; } = [];

    /// <summary>
    /// One point per day of the period, for the chart.
    /// </summary>
    /// <remarks>
    /// A month's total cannot show the shape of the month. A client whose mail
    /// was fine until the 14th and has been half-rejected since reads as "93%
    /// protected", which is accurate and tells them nothing they can act on.
    /// </remarks>
    public IReadOnlyList<DayPoint> Daily { get; init; } = [];

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }

    /// <summary>
    /// Messages the receiving provider overrode: forwarded, or its own policy.
    /// </summary>
    /// <remarks>
    /// Counted in Messages and deliberately absent from the source tables,
    /// because a mailing list breaking authentication is expected behavior
    /// rather than a finding. That makes the tables sum to less than the
    /// headline, and a client who adds them up and finds a gap has no way to
    /// know it was deliberate.
    /// </remarks>
    public long OverriddenMessages { get; init; }

    public long PreviousMessages { get; init; }
    public long PreviousPassing { get; init; }

    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);

    public double PreviousPassRate =>
        PreviousMessages == 0 ? 0 : Math.Round(PreviousPassing * 100.0 / PreviousMessages, 1);

    /// <summary>True when there is a previous period to compare against at all.</summary>
    public bool HasComparison => PreviousMessages > 0;

    /// <summary>
    /// Sources with nothing failing at all.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes the failing ones, even though those are also the
    /// client's own mail. The three buckets go into three tables in the
    /// report, and a source appearing in two of them with two different
    /// message counts reads as a contradiction rather than as nuance.
    /// </remarks>
    public IReadOnlyList<ReportSource> LegitimateSources =>
        [.. Sources.Where(s => s.IsClean).OrderByDescending(s => s.Messages)];

    /// <summary>
    /// The same sources, gathered under the service they belong to.
    /// </summary>
    /// <remarks>
    /// One real domain's August had 630 clean sources, of which 618 were
    /// Microsoft's load balancers. Listed individually, fifteen were printed
    /// and the other 606 became "and 606 more" - a customer being shown their
    /// own mail host as six hundred anonymous addresses, with the dozen
    /// sources that were actually worth reading buried underneath. Gathered,
    /// it is "Microsoft 365, 1,756 messages" and then those dozen.
    ///
    /// Only services <see cref="SenderCatalog"/> recognizes are gathered;
    /// everything else keeps its own address and its own row, so nothing is
    /// merged on a guess.
    /// </remarks>
    public IReadOnlyList<ReportSender> LegitimateSenders =>
        [.. LegitimateSources
            .GroupBy(s => SenderCatalog.Label(s.SourceIp), StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var service = SenderCatalog.Identify(g.First().SourceIp) is not null;
                var only = g.Count() == 1 ? g.First() : null;

                return new ReportSender
                {
                    // The catalog first, because "Microsoft 365" beats any
                    // reverse name its load balancers carry. Where it does not
                    // recognise the sender, the reverse name is what turns a
                    // row of digits into something a client can say yes or no
                    // to - and a row they cannot read is a row they skip.
                    Name = service || only is not { IsNamed: true } ? g.Key : only.ReverseName,
                    IsService = service,
                    SourceIp = service ? "" : only?.SourceIp ?? "",
                    Addresses = g.Count(),
                    Messages = g.Sum(s => s.Messages),
                    Domains = [.. g.SelectMany(s => s.Domains).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal)],
                };
            })
            .OrderByDescending(s => s.Messages)];

    /// <summary>
    /// Sources that have never once sent authenticated mail for this client.
    /// </summary>
    /// <remarks>
    /// A source that has EVER passed for the domain is the client's own mail
    /// path, whatever a particular failing row looks like: a mail gateway
    /// signing on the customer's behalf breaks a share of its own signatures
    /// in transit, and those rows prove nothing on their own. Judging them
    /// individually put a customer's own relay under "who tried to send mail
    /// as you" with 177 messages against it - the report accusing the client's
    /// own infrastructure. Passing even once is the thing a forger cannot do.
    /// </remarks>
    public IReadOnlyList<ReportSource> ImpersonatingSources =>
        [.. Sources.Where(s => !s.IsClean && s.Passing == 0 && !s.Authenticated)
                   .OrderByDescending(s => s.Failing)];

    /// <summary>
    /// Real senders losing the client's mail: the client's own paths that
    /// break sometimes, and third-party services signing as themselves.
    /// </summary>
    public IReadOnlyList<ReportSource> MisconfiguredSources =>
        [.. Sources.Where(s => !s.IsClean && (s.Passing > 0 || s.Authenticated))
                   .OrderByDescending(s => s.Failing)];

    /// <summary>
    /// The number that answers "what am I paying for". Messages that failed
    /// authentication while a policy was in force to act on them.
    /// </summary>
    public long MessagesActedOn =>
        Domains.Where(d => d.IsEnforcing).Sum(d => d.Messages - d.Passing);

    public bool EveryDomainEnforcing => Domains.Count > 0 && Domains.All(d => d.IsEnforcing);

    /// <summary>
    /// Domains losing enough of their own mail to be worth saying, worst
    /// first.
    /// </summary>
    /// <remarks>
    /// Read before anything is called protected. An estate average cannot
    /// answer this question and will confidently answer it wrongly: three
    /// domains at 100%, 100% and 45.5% come to 96.6% overall, so every
    /// estate-wide check passes while one domain loses more than half its
    /// mail. A client whose invoices stopped arriving does not care what the
    /// other two domains did.
    /// </remarks>
    public IReadOnlyList<ReportDomainHealth> StrugglingDomains =>
        [.. Domains.Where(d => d.IsStruggling).OrderBy(d => d.PassRate)];

    /// <summary>The client's own messages that failed, across the domains that are struggling.</summary>
    public long StrugglingMessages => StrugglingDomains.Sum(d => d.Failing);

    // ---- the inventory ------------------------------------------------------

    /// <summary>
    /// What a source is, for the table a client is asked to confirm.
    /// </summary>
    /// <remarks>
    /// The order of the tests is the whole argument. Passing even once for the
    /// domain settles it as the client's own path before anything else is
    /// asked, because that is the thing a forger cannot do - and judging the
    /// failing rows first is exactly how a gateway carrying a customer's own
    /// outbound ended up printed under "who tried to send mail as you".
    ///
    /// Only then does the catalog separate the two unproven cases, and it is
    /// separating "ask the customer whether they signed up for this" from
    /// "nobody can account for this at all". A recognised operator is not
    /// innocence: a shared ESP is where an unauthorised sender hides most
    /// comfortably. It is the difference between a question and an alarm.
    /// </remarks>
    public static SenderClass ClassOf(ReportSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        if (source.Retired) { return SenderClass.Retired; }
        if (source.Messages == 0) { return SenderClass.Retired; }
        if (source.IsClean) { return SenderClass.Approved; }
        if (source.Passing > 0 || source.Authenticated) { return SenderClass.Misconfigured; }

        // Never authenticated. A name the catalog knows makes it a question
        // for the customer; anything else is a finding.
        return SenderCatalog.Identify(source.SourceIp) is not null
               || Intelligence.SourceCatalog.Identify(source.SourceIp) is not null
            ? SenderClass.Unidentified
            : SenderClass.Suspicious;
    }

    /// <summary>Every source in the period, under the heading it belongs to.</summary>
    public IReadOnlyList<IGrouping<SenderClass, ReportSource>> Inventory =>
        [.. Sources
            .GroupBy(ClassOf)
            .OrderBy(g => (int)g.Key)];

    /// <summary>Sources under one heading, busiest first.</summary>
    public IReadOnlyList<ReportSource> InventoryOf(SenderClass which) =>
        [.. Sources.Where(s => ClassOf(s) == which).OrderByDescending(s => s.Messages)];

    // ---- why mail failed ----------------------------------------------------

    /// <summary>
    /// The failures split by cause rather than counted as one red total.
    /// </summary>
    /// <remarks>
    /// "1,204 messages failed" is a number to worry about. "1,100 of them are
    /// a service signing as itself, 90 are forwarding, 14 are nobody we can
    /// account for" is three different afternoons, two of which are somebody
    /// else's. This is the split that decides which.
    /// </remarks>
    public IReadOnlyList<(string Cause, long Messages, string Meaning)> FailureCauses
    {
        get
        {
            var spf = Sources.Sum(s => s.FailedSpfNotAligned);
            var dkim = Sources.Sum(s => s.FailedDkimNotAligned);
            var both = Sources.Sum(s => s.FailedBoth);

            return
            [
                .. new (string, long, string)[]
                {
                    ("SPF passed, did not align", spf,
                     "The sending server was authorised by its own domain rather than yours. A service sending on "
                     + "your behalf without being set up to sign as you."),
                    ("DKIM verified, did not align", dkim,
                     "The signature was valid and belonged to the sender rather than to you. Usually the same "
                     + "cause, and usually fixed by turning on custom DKIM at the vendor."),
                    ("Neither check passed", both,
                     "Nothing verified. Forwarding and mailing lists land here legitimately; so does anybody "
                     + "sending as you."),
                    ("Handled by the receiver", OverriddenMessages,
                     "The receiver broke the signature itself - forwarding, or a mailing list - recorded why, and "
                     + "declined to apply your policy. Expected, and not worth chasing."),
                }.Where(row => row.Item2 > 0),
            ];
        }
    }

    // ---- what to do ---------------------------------------------------------

    /// <summary>
    /// The register the report ends on: every finding with an owner and a
    /// definition of done.
    /// </summary>
    /// <remarks>
    /// Derived rather than stored, so it cannot drift from the figures above
    /// it, and ordered by what would cost the client most. A report ending in
    /// "consider moving to p=reject" ends in nothing; these end in something
    /// somebody can put a date against.
    /// </remarks>
    public IReadOnlyList<RemediationItem> Remediation
    {
        get
        {
            var items = new List<RemediationItem>();

            // Worst first: mail that is not arriving, because that is the one
            // with a cost the client can already feel.
            foreach (var domain in StrugglingDomains)
            {
                items.Add(new RemediationItem
                {
                    Priority = "Critical",
                    Finding = $"{domain.Domain} is losing {domain.Failing:N0} of its own message(s) "
                            + $"({domain.PassRate:0.#}% arriving).",
                    Impact = domain.IsEnforcing
                        ? "Real mail is being refused or filed as junk by the receiving provider right now."
                        : "Real mail would be refused the moment this domain's policy is raised.",
                    Action = "Name every sender in the inventory below, then correct the ones marked as needing it "
                           + "before touching the policy.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = $"{domain.Domain} above {HealthyPassRate:0}% for seven consecutive days.",
                });
            }

            foreach (var source in InventoryOf(SenderClass.Misconfigured).Take(5))
            {
                items.Add(new RemediationItem
                {
                    Priority = "High",
                    Finding = $"{source.Display} is sending as you and {source.Failing:N0} message(s) are not "
                            + "provably yours.",
                    Impact = "These are your own messages. They are at risk of being refused under an enforcing "
                           + "policy, and some are already being filed as junk.",
                    Action = source.Authenticated
                        ? $"This service signs as {source.AuthenticatedFor} rather than as you. Turn on custom "
                        + "DKIM for your domain at the vendor, or authorise it in SPF."
                        : "Confirm which system this is, then authorise it properly rather than leaving it "
                        + "half-configured.",
                    Owner = "Whoever runs this service, with your IT provider",
                    Validation = "Seven consecutive days of aligned mail from this source.",
                });
            }

            foreach (var source in InventoryOf(SenderClass.Suspicious).Take(3))
            {
                items.Add(new RemediationItem
                {
                    Priority = source.OtherClientsAffected > 0 ? "High" : "Medium",
                    Finding = $"{source.Display} sent {source.Failing:N0} message(s) as you and never "
                            + "authenticated once"
                            + (source.OtherClientsAffected > 0
                                ? $", and was seen against {source.OtherClientsAffected} unrelated organisation(s)."
                                : "."),
                    Impact = EveryDomainEnforcing
                        ? "Already refused or filed as junk by the receiving provider, because your policy is "
                        + "enforcing. This is the protection working."
                        : "Not currently stopped: your policy asks receivers to do nothing about it.",
                    Action = EveryDomainEnforcing
                        ? "No action needed. Recorded so the pattern is visible if it grows."
                        : "Raise the policy so receivers are asked to refuse it.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "The volume stops, or the policy is enforcing and it is being refused.",
                });
            }

            // Only after the mail is right. Told to raise a policy first, an
            // MSP breaks a customer's invoicing and learns not to trust the
            // report.
            foreach (var domain in Domains.Where(d => d is { IsEnforcing: false, IsStruggling: false, Messages: > 0 }))
            {
                items.Add(new RemediationItem
                {
                    Priority = "Medium",
                    Finding = $"{domain.Domain} is at p={domain.Policy}, so receivers are asked to do nothing "
                            + "about mail that fails.",
                    Impact = "Anybody can send mail as this domain today and have it delivered.",
                    Action = domain.Readiness == "Ready"
                        ? "Its own mail authenticates. Move to p=quarantine, then to p=reject."
                        : $"Account for the {domain.Failing:N0} failing message(s) first, then move to "
                        + "p=quarantine.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "The policy is published and the domain's own mail keeps arriving.",
                });
            }

            foreach (var source in InventoryOf(SenderClass.Retired).Take(3))
            {
                items.Add(new RemediationItem
                {
                    Priority = "Low",
                    Finding = $"{source.Display} sent as you last period and not at all this one.",
                    Impact = "Either a service was retired and is still authorised to send as you, or something "
                           + "stopped working quietly.",
                    Action = "Confirm which. If it is retired, remove it from SPF so the authorisation goes with it.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "Either mail resumes, or the authorisation is removed.",
                });
            }

            return [.. items.OrderBy(i => i.Rank)];
        }
    }
}
