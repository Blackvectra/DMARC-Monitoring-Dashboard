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
    /// handed a row of digits and asked whether they recognized it. Nobody
    /// recognizes an address; they recognize "a Comcast connection in Denver"
    /// or "one of our own servers".
    ///
    /// Read for display and never for judgement. A PTR is written by whoever
    /// holds the address, so it identifies a sender the way a return address
    /// on an envelope does - enough to recognize a provider, nowhere near
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

    /// <summary>
    /// Failing messages where SPF alone passed, for the wrong domain.
    /// </summary>
    /// <remarks>
    /// Exclusive of <see cref="FailedBothNotAligned"/>, and it has to be. A
    /// message that passed both checks without aligning belongs to exactly one
    /// row of a table whose rows are added up - counted in both, the report
    /// says more mail failed than was ever sent, which is the one arithmetic
    /// error a client will find.
    /// </remarks>
    public long FailedSpfNotAligned { get; init; }

    /// <summary>Failing messages where DKIM alone verified, for the wrong domain.</summary>
    public long FailedDkimNotAligned { get; init; }

    /// <summary>
    /// Failing messages where SPF and DKIM both passed, and neither was about
    /// the domain in the From line.
    /// </summary>
    /// <remarks>
    /// Its own row rather than folded into either of the others, because it
    /// says something neither of them does: the sender is fully configured,
    /// correctly, entirely as itself. There is nothing broken at their end to
    /// find - the work is to make them sign as the customer.
    /// </remarks>
    public long FailedBothNotAligned { get; init; }

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

    /// <summary>The client's own path, or a recognized service, losing some of its mail.</summary>
    Misconfigured,

    /// <summary>
    /// Never authenticated, but a security gateway passing mail on - usually a
    /// recipient's filter re-sending the client's own message. Not an attack.
    /// </summary>
    Relayed,

    /// <summary>Never authenticated, but operated by somebody the catalog recognizes.</summary>
    Unidentified,

    /// <summary>Never authenticated, and nothing recognizes the operator.</summary>
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

    /// <summary>
    /// How long this should take, from the date on the report.
    /// </summary>
    /// <remarks>
    /// A register without dates is a list of opinions. These are the spans an
    /// MSP can commit to without asking anybody: a week for mail that is not
    /// arriving, a fortnight for a vendor to turn something on, a month for a
    /// policy change, six weeks for tidying an inventory.
    /// </remarks>
    public string Target => Priority switch
    {
        "Critical" => "7 days",
        "High" => "14 days",
        "Medium" => "30 days",
        _ => "45 days",
    };
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
/// <summary>
/// One line of what the month's monitoring covered.
/// </summary>
/// <remarks>
/// A client whose estate is healthy gets a report that says, correctly, that
/// there is nothing to do - and a page of white space under it. That is the
/// report the client who is happiest with you receives, and it reads as an
/// invoice with no work attached. These are the facts that say what was
/// watched and what it stopped, which is the thing being paid for.
/// </remarks>
public sealed record ReportFact
{
    public required string Label { get; init; }
    public required string Value { get; init; }
    public required string Note { get; init; }
}

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
    /// be arbitrary. A single unrecognized sender has exactly one, and the
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

    /// <summary>
    /// Messages whose SPF check passed AND was about this domain.
    /// </summary>
    /// <remarks>
    /// Not the same as "SPF passed", and the difference is the whole subject.
    /// A service sending on the client's behalf passes SPF for its own
    /// envelope domain every time; that is the sender proving it is itself,
    /// which DMARC does not accept as the client proving it is them. Printed
    /// as one number they read as a domain that is fine.
    /// </remarks>
    public long SpfAligned { get; init; }

    /// <summary>Messages whose DKIM signature verified AND was signed as this domain.</summary>
    public long DkimAligned { get; init; }

    /// <summary>Distinct addresses that sent mail for this domain which failed.</summary>
    public int FailingSources { get; init; }

    /// <summary>
    /// Failed messages from addresses that never authenticated for this
    /// client in the period - not once passed DMARC, not once proved
    /// themselves for any domain. Forged, not the domain's own.
    /// </summary>
    public long Forged { get; init; }

    /// <summary>The domain's own mail: everything that was not forged.</summary>
    public long OwnMessages => Math.Max(0, Messages - Forged);

    /// <summary>The domain's own messages that failed.</summary>
    public long OwnFailing => Math.Max(0, OwnMessages - Passing);

    /// <summary>
    /// How much of the domain's OWN mail authenticated.
    /// </summary>
    /// <remarks>
    /// This, not <see cref="PassRate"/>, decides whether a domain is losing
    /// mail. Judged on the total, a domain under a spoofing run - 300 real
    /// messages all passing, 700 forged - read as 30% arriving and "raising a
    /// policy now would stop them", which told the one client who most needed
    /// to enforce not to. The forged mail is what a policy is FOR.
    /// </remarks>
    public double OwnPassRate => OwnMessages == 0 ? 0 : Math.Round(Passing * 100.0 / OwnMessages, 1);

    /// <summary>
    /// True when the policy actually covers this domain's mail: enforcing,
    /// applied to all of it, and not undone for subdomains.
    /// </summary>
    /// <remarks>
    /// <c>p=reject; sp=none</c> refuses nothing sent as a subdomain, and
    /// <c>pct=25</c> lets three quarters of failures through. Both are real
    /// rollout states, and both were being described to the client as
    /// "already refused... this is the protection working".
    /// </remarks>
    public bool IsFullyEnforcing =>
        IsEnforcing && Pct >= 100 && SubdomainPolicy is not "none";

    public double SpfAlignedRate => Messages == 0 ? 0 : Math.Round(SpfAligned * 100.0 / Messages, 1);
    public double DkimAlignedRate => Messages == 0 ? 0 : Math.Round(DkimAligned * 100.0 / Messages, 1);

    /// <summary>
    /// The policy receivers were applying during the period, written as the
    /// record it came from.
    /// </summary>
    /// <remarks>
    /// Rebuilt from what the reports carried rather than read from DNS today,
    /// because a report describes a period: the record may have changed since,
    /// and printing today's beside last month's figures is the same mistake as
    /// dating the figures wrongly.
    /// </remarks>
    public string Record
    {
        get
        {
            if (!PolicyKnown) { return "not known for this period"; }

            var record = $"v=DMARC1; p={Policy}";
            if (SubdomainPolicy.Length > 0) { record += $"; sp={SubdomainPolicy}"; }
            if (Pct != 100) { record += $"; pct={Pct}"; }
            if (StrictAlignment) { record += "; adkim=s"; }
            return record;
        }
    }

    /// <summary>What to do about this domain, in one line.</summary>
    public string Recommended =>
        Messages == 0 ? "Confirm whether this domain sends mail at all."
        // "Before the policy is raised" read, on a domain already at
        // p=quarantine, as though it were not enforcing at all. Name the step.
        : IsStruggling ? Policy switch
        {
            "reject" => "Correct the senders below: their mail is being refused now.",
            "quarantine" => "Correct the senders below before moving to p=reject.",
            _ => "Correct the senders below before moving to p=quarantine.",
        }
        : IsEnforcing ? "Nothing. Keep watching."
        : PassRate >= 99 ? $"Move from p={Policy} to p=quarantine."
        : $"Account for the {Failing:N0} failing message(s), then move to p=quarantine.";

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
    public bool IsStruggling => OwnMessages > 0 && OwnPassRate < ClientReport.HealthyPassRate;

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

    /// <summary>
    /// The last day covered when the month is still in progress, or null
    /// for a month that has ended.
    /// </summary>
    public DateOnly? Through { get; init; }

    /// <summary>The dates the report covers, said as a sentence.</summary>
    public string Covers => Through is { } through
        ? string.Create(CultureInfo.InvariantCulture,
            $"Covers {Period.Start:MMM d, yyyy} to {through:MMM d, yyyy}; the month is still in progress.")
        : string.Create(CultureInfo.InvariantCulture,
            $"Covers {Period.Start:MMM d, yyyy} to {Period.End:MMM d, yyyy}.");

    /// <summary>" so far" while the month is still running.</summary>
    private string SoFar => Through is null ? "" : " so far";

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
    /// Messages a receiver refused or filed as junk because the policy told
    /// it to. The protection, as delivered, rather than as configured.
    /// </summary>
    /// <remarks>
    /// Taken from the dispositions the receivers reported, not from the
    /// failure count: a message that failed under p=none was delivered, and
    /// counting it here would tell a client they were protected by a policy
    /// that asked for nothing.
    /// </remarks>
    public long Stopped => Daily.Sum(d => d.Rejected + d.Quarantined);

    /// <summary>
    /// True when no receiver said anything about this client in this period.
    /// </summary>
    /// <remarks>
    /// Asked of the domains and the sources as well as the total, not of the
    /// total alone. They are filled by the same query and cannot disagree in
    /// practice, but "nothing at all was observed" is the premise the register
    /// uses to refuse to give an all-clear, and a premise that strong should
    /// not rest on one field being right.
    /// </remarks>
    public bool NothingWasReported =>
        Messages == 0 && !Domains.Any(d => d.Messages > 0) && !Sources.Any(s => s.Messages > 0);

    /// <summary>
    /// What the month's monitoring covered, for the client paying for it.
    /// </summary>
    /// <remarks>
    /// The report for a healthy estate correctly says there is nothing to do,
    /// and then stops - half a page, sent monthly, to the client who is
    /// happiest with the service. Nothing on it says what was watched, how
    /// much was read, or what the policy turned away, so the one client with
    /// no problems is the one with no evidence of the work.
    /// </remarks>
    public IReadOnlyList<ReportFact> Covered
    {
        get
        {
            var facts = new List<ReportFact>();

            var days = Daily.Count;
            var reported = Daily.Count(d => d.Reported);
            if (days > 0)
            {
                facts.Add(new ReportFact
                {
                    Label = "Days covered",
                    Value = $"{reported} of {days}{SoFar}",

                    // Said plainly, because it qualifies everything above it.
                    // A month with four days of reports in it can show a
                    // perfect pass rate, and a client reading "100%" is
                    // entitled to know it describes four days.
                    Note = reported switch
                    {
                        0 => "No receiver reported on any day of this period, so the figures above describe "
                           + "nothing that was observed.",
                        _ when reported == days && Through is { } through =>
                            $"The month is not over. Every day to {through:MMMM d} was reported on by at least one receiver.",
                        _ when reported == days =>
                            "Every day of the period was reported on by at least one receiver.",
                        _ => $"The figures above describe the {reported} day(s) that were reported on. A day with "
                           + "no report is not a day with no mail: receivers miss runs.",
                    },
                });
            }

            facts.Add(new ReportFact
            {
                Label = "Messages examined",
                Value = Messages.ToString("N0", CultureInfo.InvariantCulture),
                Note = "Every message that claimed to come from your domains, as the receiving providers "
                     + "described it.",
            });

            facts.Add(new ReportFact
            {
                Label = "Domains watched",
                Value = Domains.Count.ToString("N0", CultureInfo.InvariantCulture),
                Note = "Their DMARC, SPF and DKIM records were read and checked over the period, not taken on "
                     + "trust from a previous month.",
            });

            var senders = LegitimateSenders.Count + InventoryOf(SenderClass.Misconfigured).Count;
            if (senders > 0)
            {
                facts.Add(new ReportFact
                {
                    Label = "Sending services identified",
                    Value = senders.ToString("N0", CultureInfo.InvariantCulture),
                    Note = "Named rather than left as addresses, so an unfamiliar one is something you can "
                         + "recognize or query.",
                });
            }

            if (Stopped > 0)
            {
                facts.Add(new ReportFact
                {
                    Label = "Turned away on your behalf",
                    Value = Stopped.ToString("N0", CultureInfo.InvariantCulture),
                    // "The protection doing its job" only when it was: at
                    // River City Boats 224 of 234 were the client's own
                    // Mailchimp and Avanan mail, sent to junk.
                    Note = Domains.Sum(d => d.OwnFailing) > 0
                        ? "Refused or filed as junk by the receiving provider because your policy said to. This "
                        + "includes mail of your own that failed the checks, not only forgeries; the findings "
                        + "above name the services."
                        : "Refused or filed as junk by the receiving provider because your policy said to. This "
                        + "is the protection doing its job.",
                });
            }

            if (OverriddenMessages > 0)
            {
                facts.Add(new ReportFact
                {
                    Label = "Forwarded, and allowed for",
                    Value = OverriddenMessages.ToString("N0", CultureInfo.InvariantCulture),
                    Note = "Mailing lists and forwarders break authentication as a matter of course. These are "
                         + "counted apart from the failures so they do not read as a problem.",
                });
            }

            return facts;
        }
    }

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
        [.. Sources.Where(s => s is { IsClean: true, Retired: false, Messages: > 0 })
                   .OrderByDescending(s => s.Messages)];

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
                    // recognize the sender, the reverse name is what turns a
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
        [.. Sources.Where(s => !s.IsClean && s.Passing == 0 && !s.Authenticated && ClassOf(s) != SenderClass.Relayed)
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
        [.. Domains.Where(d => d.IsStruggling).OrderBy(d => d.OwnPassRate)];

    /// <summary>The client's own messages that failed, across the domains that are struggling.</summary>
    public long StrugglingMessages => StrugglingDomains.Sum(d => d.OwnFailing);

    /// <summary>
    /// Every domain enforcing with nothing undoing it: no <c>sp=none</c>, no
    /// <c>pct</c> below 100. The only state in which forged mail can be
    /// called refused.
    /// </summary>
    public bool EveryDomainFullyEnforcing => Domains.Count > 0 && Domains.All(d => d.IsFullyEnforcing);

    /// <summary>
    /// Below this, a finding is real and not urgent.
    /// </summary>
    /// <remarks>
    /// The register ranked a one-message finding as High beside a
    /// twenty-three-message one, because the class decided the priority and
    /// the volume decided nothing. A client reading five High rows, four of
    /// them worth a single message, learns to skip the column.
    /// </remarks>
    public const int MaterialMessages = 10;

    /// <summary>
    /// Names the sources in a finding: the first few, then a count.
    /// </summary>
    /// <remarks>
    /// The names are what somebody has to quote to a vendor, so they belong in
    /// the sentence rather than in a table the reader has to go and find. Busiest
    /// first, because that is the one to start with, and four because a fifth
    /// makes the cell taller than the row beside it.
    /// </remarks>
    /// <summary>
    /// Who operates a source: the catalogue's name for it, else the
    /// registrable part of its reverse name, else the bare address.
    /// </summary>
    private static string Operator(ReportSource source) =>
        SenderCatalog.Identify(source.SourceIp) is not null ? SenderCatalog.Label(source.SourceIp)
        : Intelligence.SourceCatalog.Identify(source.ReverseName) is { } known ? known.Name
        : Intelligence.SourceCatalog.OrganizationalDomain(source.ReverseName) is { } org ? org
        : source.Display;

    /// <summary>
    /// The sources, named by who operates them.
    /// </summary>
    /// <remarks>
    /// One name per operator, not per server. Named per server, a client was
    /// asked to confirm "psm.knowbe4.com, psm.knowbe4.com" and four
    /// mailout99x.ngpweb.com hosts by name - the same two companies, six
    /// times - and the one unfamiliar sender in the list was buried under
    /// them.
    /// </remarks>
    private static string Name(IReadOnlyList<ReportSource> sources)
    {
        const int shown = 4;

        var ordered = sources
            .GroupBy(Operator, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Name: g.Key, Count: g.Count(), Failing: g.Sum(s => s.Failing), Messages: g.Sum(s => s.Messages)))
            .OrderByDescending(g => g.Failing).ThenByDescending(g => g.Messages)
            .Select(g => g.Count > 1 ? $"{g.Name} ({g.Count} servers)" : g.Name)
            .ToList();

        var listed = ordered.Take(shown).ToList();
        if (ordered.Count > shown) { return $"{string.Join(", ", listed)} and {ordered.Count - shown} more"; }
        return listed.Count <= 1 ? string.Concat(listed) : $"{string.Join(", ", listed[..^1])} and {listed[^1]}";
    }

    /// <summary>
    /// A security gateway or the client's own mail platform: something that
    /// passes their mail on rather than sending it.
    /// </summary>
    /// <remarks>
    /// These break a signature in transit - a banner stapled on, a relay that
    /// changes the envelope - and asking the vendor to "sign as you" is the
    /// wrong fix: Avanan is not going to DKIM-sign as the client, and
    /// Microsoft 365 already can. The fix is in the gateway's own settings.
    /// </remarks>
    private static bool PassesMailOn(ReportSource source) =>
        Intelligence.SourceCatalog.Identify(source.ReverseName)?.Kind
            is Intelligence.SourceKind.SecurityGateway or Intelligence.SourceKind.MailProvider
        // Recognized by address rather than by name: Microsoft's and Google's
        // ranges are in the sender catalogue, and a client's own mailbox
        // provider failing is forwarding or a relay, not a vendor to ask to
        // sign. Asked to "arrange custom DKIM signing with Microsoft 365",
        // an MSP would rightly wonder what the report thinks M365 is.
        || Operator(source) is "Microsoft 365" or "Google Workspace" or "Google";

    /// <summary>
    /// A bare address: not in either catalogue, and no name to go on.
    /// </summary>
    private static bool IsUnnamed(ReportSource source) =>
        SenderCatalog.Identify(source.SourceIp) is null
        && Intelligence.SourceCatalog.Identify(source.ReverseName) is null
        && Intelligence.SourceCatalog.OrganizationalDomain(source.ReverseName) is null;

    private static int Operators(IReadOnlyList<ReportSource> sources) =>
        sources.Select(Operator).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    /// <summary>
    /// The one-line verdict an executive reads and nothing else.
    /// </summary>
    /// <remarks>
    /// Written to be quotable in a meeting: a state, the number behind it, and
    /// what it means for a decision about enforcement. "DMARC passed 98% of
    /// messages" is a fact nobody can act on; "ready to enforce once two
    /// senders are corrected" is a decision.
    ///
    /// Never flatters. A domain losing mail outranks a good average, because
    /// an average across an estate is how a broken domain stays invisible.
    /// </remarks>
    public string Verdict => VerdictCore + CoverageCaveat;

    /// <summary>
    /// What the client has to decide, when there is something only they can
    /// confirm. Null when nothing is waiting on them.
    /// </summary>
    /// <remarks>
    /// The register says what to do; this says what the provider cannot do
    /// without the client. Services sending as them that are not set up to
    /// prove it are either theirs - and a vendor has to be asked to sign as
    /// them - or not theirs. Only the client knows which, and until they say,
    /// nothing moves.
    /// </remarks>
    public string? DecisionRequested =>
        DecisionItems.Count == 0 ? null : string.Join(" ", DecisionItems.Select(i => $"{i.Label}: {i.Text}"));

    /// <summary>
    /// The decision, one labelled line per thing to settle.
    /// </summary>
    /// <remarks>
    /// Run together it was a paragraph a client had to parse to find what was
    /// being asked of whom. One line per service kind, and one for the policy.
    /// </remarks>
    public IReadOnlyList<(string Label, string Text)> DecisionItems
    {
        get
        {
            var broken = InventoryOf(SenderClass.Misconfigured);
            if (broken.Count == 0) { return []; }

            var who = ProviderIsUnnamed ? "your IT provider" : ProviderName;
            var hold = Domains.Where(d => d.IsEnforcing && d.Policy != "reject").Select(d => $"p={d.Policy}")
                .Distinct().FirstOrDefault();
            var domain = Domains.Count == 1 ? Domains[0].Domain : "your domain";

            var unnamed = broken.Where(x => !PassesMailOn(x) && IsUnnamed(x)).ToList();
            var vendors = broken.Where(x => !PassesMailOn(x) && !IsUnnamed(x)).ToList();
            var gateways = broken.Where(PassesMailOn).ToList();
            var parts = new List<(string, string)>();

            if (vendors.Count > 0)
            {
                var one = Operators(vendors) == 1;
                parts.Add((Name(vendors),
                    $"Confirm {(one ? "it is an approved sender" : "they are approved senders")}, and authorize {who} "
                  + $"to arrange custom DKIM signing for {domain} with {(one ? "it" : "each")}."));
            }

            if (unnamed.Count > 0)
            {
                // Nobody can arrange DKIM signing with an address. What the
                // client can do is say whose it is.
                var one = unnamed.Count == 1;
                parts.Add((Name(unnamed),
                    $"Tell {who} whether you recognize {(one ? "this address" : "these addresses")}. {(one ? "It" : "They")} "
                  + $"sent mail as {domain} that did not pass DMARC, and nothing on record names the operator. "
                  + "If it is a service of yours, it needs custom DKIM signing like any other; if not, somebody is "
                  + "sending as you."));
            }

            if (gateways.Count > 0)
            {
                var one = Operators(gateways) == 1;

                // "May", and "validate" first: a relay that alters a message
                // is the likeliest reading of this pattern, not the only one,
                // and a report covering part of a month should not state it as
                // settled.
                parts.Add((Name(gateways),
                    $"Confirm {(one ? "it handles" : "they handle")} your outbound mail. {(one ? "It" : "They")} may modify "
                  + "or relay messages in a way that invalidates their DKIM signature; authorize "
                  + $"{who} to validate the mail flow and set {(one ? "it" : "each")} to preserve the signature or "
                  + $"re-sign as {domain} after processing."));
            }

            var these = Operators(broken) == 1 ? "this passes" : "these pass";
            if (hold is not null)
            {
                parts.Add(("Policy",
                    $"Keep {hold} in place. Do not move to p=reject until {these} "
                  + "DMARC and a fuller reporting period has been reviewed."));
            }
            else if (Domains.Any(d => !d.IsEnforcing && d.Messages > 0))
            {
                // A domain only being watched needs saying just as much: the
                // next step there is p=quarantine, and the same senders stand
                // in its way.
                parts.Add(("Policy",
                    $"Stay at p=none (monitoring) for now. Move to p=quarantine once {these} DMARC, with a "
                  + "full month reviewed first."));
            }

            return parts;
        }
    }

    /// <summary>
    /// Appended to the verdict when reports cover less than half the period.
    /// </summary>
    /// <remarks>
    /// "Days covered" was already stated, on page three. A verdict built on
    /// fourteen days of a thirty-day month is directional, and the reader who
    /// stops after the first paragraph - most of them - is owed that in the
    /// same paragraph, not two pages later.
    /// </remarks>
    private string CoverageCaveat
    {
        get
        {
            if (NothingWasReported || Daily.Count == 0) { return ""; }

            var reported = Daily.Count(d => d.Reported);
            return reported * 2 < Daily.Count
                ? $" Confidence is limited: reports arrived for {reported} of {Daily.Count} days{SoFar}, so treat this as "
                + "directional until a fuller month is in."
                : "";
        }
    }

    private string VerdictCore
    {
        get
        {
            if (Messages == 0) { return "No mail was reported for this client in this period."; }

            if (StrugglingDomains.Count > 0)
            {
                // Said in terms of the step that is next, because "not ready
                // for enforcement" is false of a domain already at
                // p=quarantine - it is enforcing, and a client reading the
                // verdict and then the record sees a contradiction. And
                // "authenticated", not "arriving": the figure is DMARC, not
                // delivery.
                //
                // "Did not pass DMARC", not "failed to authenticate": most of
                // these authenticate perfectly well, as the vendor, which is
                // the whole problem. And nothing here says what receivers DID
                // with them - that is a separate count, stated separately,
                // because it also includes forged mail and a reader who adds
                // the two up gets neither.
                //
                // And the count is the named services', not the domain's
                // total. Those are the figures the register and the sender
                // table use; a headline of 225 over a register of 224 and an
                // inventory row of 229 read as one number counted three ways.
                // 229 is everything those services sent, some of which
                // passed; 224 is what did not, and is what the headline says.
                var worst = StrugglingDomains[0];
                var services = InventoryOf(SenderClass.Misconfigured)
                    .Where(x => x.Domains.Contains(worst.Domain, StringComparer.OrdinalIgnoreCase)).ToList();
                var failed = services.Count > 0
                    ? $"{services.Sum(x => x.Failing):N0} message(s) from {Operators(services)} of your sending "
                      + $"service(s) did not pass DMARC"
                      + (services.Sum(x => x.FailedBothNotAligned) is var vendor and > 0
                          ? $" ({vendor:N0} of them authenticated as the service's own domain rather than as {worst.Domain})"
                          : "")
                    : $"{worst.OwnFailing:N0} message(s) from your own senders did not pass DMARC "
                      + $"({worst.OwnPassRate:0.#}% did)";
                var verdict = worst.Policy switch
                {
                    "reject" => $"Losing mail now. {worst.Domain} is at p=reject, and {failed}, so receivers are "
                              + "told to refuse them. Correct the senders named below.",
                    "quarantine" => $"Not ready for p=reject. {worst.Domain} is already at p=quarantine, and {failed}; "
                                  + "under p=reject they would be refused outright. Correct the senders named below "
                                  + "before moving further.",
                    _ => $"Not ready for enforcement. {worst.Domain} is at p={worst.Policy}, and {failed}; raising "
                       + "the policy now would stop them. Correct the senders named below first.",
                };

                return Stopped > 0
                    ? verdict + $" Separately, receivers reported quarantining or refusing {Stopped:N0} message(s) "
                      + "under the current policy; that count includes forged mail, not only yours."
                    : verdict;
            }

            var broken = Operators(InventoryOf(SenderClass.Misconfigured));

            // Every domain not enforcing, whether or not it sent anything
            // this month. Counted only the ones with mail, a p=none domain
            // that happened to be quiet dropped out and the verdict read
            // "Protected. Every domain is enforcing" over a domain anybody
            // could send as tomorrow. A policy is about what a domain
            // permits, not about what it did in a given month.
            var watching = Domains.Count(d => !d.IsEnforcing);

            if (watching > 0 && broken > 0)
            {
                return $"Conditional readiness. {PassRate:0.#}% of the mail sent using your name was provably yours, and {broken} "
                     + $"service(s) still need correcting before {(watching == 1 ? "the domain that is" : $"the {watching} domains")} "
                     + "only being watched can be protected.";
            }

            if (watching > 0)
            {
                return $"Ready for enforcement. {PassRate:0.#}% of the mail sent using your name was provably yours and no sender "
                     + $"needs correcting, so {(watching == 1 ? "the domain" : $"the {watching} domains")} "
                     + "only being watched can be moved to quarantine.";
            }

            // "Of the mail sent using your name", not "of your mail". The
            // figure counts everything that claimed to be the client,
            // forgeries included, so a domain under a spoofing run read
            // "Protected... 78.7% of your mail is provably yours" - which
            // sounds like a fifth of the client's own mail failing, sitting
            // under a verdict that says it is not.
            return broken > 0
                ? $"Protected, with work outstanding. Every domain is enforcing and {PassRate:0.#}% of the mail "
                + $"sent using your name was provably yours; {broken} of your service(s) still {(broken == 1 ? "sends" : "send")} mail that "
                + "cannot prove it."
                : $"Protected. Every domain is enforcing, {PassRate:0.#}% of the mail sent using your name was "
                + "provably yours, and no sender of yours needs correcting.";
        }
    }

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
    /// "nobody can account for this at all". A recognized operator is not
    /// innocence: a shared ESP is where an unauthorized sender hides most
    /// comfortably. It is the difference between a question and an alarm.
    /// </remarks>
    public static SenderClass ClassOf(ReportSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        if (source.Retired) { return SenderClass.Retired; }
        if (source.Messages == 0) { return SenderClass.Retired; }
        if (source.IsClean) { return SenderClass.Approved; }
        if (source.Passing > 0 || source.Authenticated) { return SenderClass.Misconfigured; }

        // A security gateway that never authenticated is somebody's filter
        // passing mail on - INKY and Proofpoint re-sending a message to the
        // recipient behind them - and it was printed in eleven of nineteen
        // September reports under "somebody pretending to be you".
        if (Intelligence.SourceCatalog.Identify(source.ReverseName)?.Kind is Intelligence.SourceKind.SecurityGateway)
        {
            return SenderClass.Relayed;
        }

        // Never authenticated. A name the catalog knows makes it a question
        // for the customer; anything else is a finding. The source catalogue
        // is keyed on host names: asked about the address, as it was, it
        // never matched anything.
        return SenderCatalog.Identify(source.SourceIp) is not null
               || Intelligence.SourceCatalog.Identify(source.ReverseName) is not null
            ? SenderClass.Unidentified
            : SenderClass.Suspicious;
    }

    /// <summary>Every source in the period, under the heading it belongs to.</summary>
    public IReadOnlyList<IGrouping<SenderClass, ReportSource>> Inventory =>
        [.. Sources
            .GroupBy(ClassOf)
            .OrderBy(g => (int)g.Key)];

    /// <summary>
    /// The client's services that sent as this domain and are not set up to
    /// prove it.
    /// </summary>
    public IReadOnlyList<ReportSource> BrokenSendersFor(ReportDomainHealth domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return [.. InventoryOf(SenderClass.Misconfigured).Where(s =>
            Domains.Count == 1 || s.Domains.Contains(domain.Domain, StringComparer.OrdinalIgnoreCase))];
    }

    /// <summary>
    /// What to do about one domain, in one line, consistent with the verdict
    /// and the decision requested.
    /// </summary>
    /// <remarks>
    /// The domain's own <see cref="ReportDomainHealth.Recommended"/> cannot
    /// see the sources, so it said "Nothing. Keep watching." beside a verdict
    /// of "3 of your services still send mail that cannot prove it" - in
    /// eleven of nineteen September reports, NRG's own among them - and "Move
    /// from p=none to p=quarantine" beside a decision box saying to stay at
    /// p=none until the services pass. The next step is the services.
    /// </remarks>
    public string WhatToDo(ReportDomainHealth domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        if (domain.Messages == 0 || domain.IsStruggling || BrokenSendersFor(domain).Count == 0)
        {
            return domain.Recommended;
        }

        return domain.Policy switch
        {
            "reject" => "Correct the named services: their failing mail is being refused now.",
            "quarantine" => "Correct the named services before moving to p=reject.",
            _ => "Correct the named services, then move to p=quarantine.",
        };
    }

    /// <summary>The readiness word, with the same knowledge of the sources.</summary>
    public string ReadinessOf(ReportDomainHealth domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return domain.Readiness == "Ready" && BrokenSendersFor(domain).Count > 0 ? "Conditional" : domain.Readiness;
    }

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
            var neither = Sources.Sum(s => s.FailedBoth);
            var bothUnaligned = Sources.Sum(s => s.FailedBothNotAligned);

            return
            [
                .. new (string, long, string)[]
                {
                    ("SPF passed, did not align", spf,
                     "The sending server was authorized by its own domain rather than yours. A service sending on "
                     + "your behalf without being set up to sign as you."),
                    ("DKIM verified, did not align", dkim,
                     "The signature was valid and belonged to the sender rather than to you. Usually the same "
                     + "cause, and usually fixed by turning on custom DKIM at the vendor."),
                    ("Both checks passed, neither aligned", bothUnaligned,
                     "SPF and DKIM both verified, but for a service's own domain rather than yours. For a "
                     + "sending vendor that means it is not set up to sign as you; a mail-security service in the "
                     + "path can produce the same pattern. The two are fixed differently."),
                    ("Neither check passed", neither,
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

            // A month with nothing in it is not a clean month.
            //
            // The register was empty for a client no receiver reported on,
            // and an empty register printed "Nothing. Every domain is
            // enforcing, its own mail is arriving, and no sender needs
            // correcting." Every one of those three claims was false for a
            // domain sitting at p=none that nobody had confirmed sends mail
            // at all - and it went out under the heading that tells a client
            // what to do next.
            if (NothingWasReported)
            {
                var watched = Domains.Where(d => !d.IsEnforcing).Select(d => d.Domain).ToList();

                items.Add(new RemediationItem
                {
                    // Nothing can be seen, and on an unenforcing domain that
                    // means nothing is stopping anybody either.
                    Priority = watched.Count > 0 ? "High" : "Medium",
                    Finding = "No receiver reported on "
                            + (Domains.Count == 1 ? Domains[0].Domain : $"{Domains.Count} domain(s)")
                            + $" in {Period.Label}, so nothing about this period can be confirmed.",
                    Impact = "Either these domains sent no mail, or the reports are not reaching us. The two are "
                           + "indistinguishable from here, and only one of them is fine"
                           + (watched.Count > 0
                               ? $". {string.Join(", ", watched)} also asks receivers to do nothing about mail "
                               + "that fails, so anybody can send as it today."
                               : "."),
                    Action = "Check that each domain's DMARC record names this service in its rua address, and that "
                           + "a report has arrived since. If a domain genuinely sends no mail, say so: it can be "
                           + "set to reject and left alone.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "A report arrives for each domain, or the domain is recorded as non-sending and "
                               + "moved to p=reject.",
                });

                return items;
            }

            // Worst first: mail that is not arriving, because that is the one
            // with a cost the client can already feel.
            foreach (var domain in StrugglingDomains)
            {
                items.Add(new RemediationItem
                {
                    Priority = "Critical",
                    // The same count the headline gives, for the same reason.
                    Finding = InventoryOf(SenderClass.Misconfigured)
                        .Where(x => x.Domains.Contains(domain.Domain, StringComparer.OrdinalIgnoreCase)).ToList() is { Count: > 0 } svc
                        ? $"{svc.Sum(x => x.Failing):N0} message(s) from "
                          + (Operators(svc) <= 4 ? Name(svc) : $"{Operators(svc)} of {domain.Domain}'s sending services")
                          + $" did not pass DMARC. Do not move to p=reject until {(Operators(svc) == 1 ? "its fix is" : "their separate fixes are")} "
                          + "complete."
                        : $"{domain.OwnFailing:N0} message(s) from {domain.Domain}'s own senders did not pass DMARC "
                          + $"({domain.OwnPassRate:0.#}% did).",
                    Impact = domain.IsEnforcing
                        ? "Real mail is being refused or filed as junk by the receiving provider right now."
                        : "Real mail would be refused the moment this domain's policy is raised.",
                    Action = "Confirm the services named are yours, identify anything still unrecognized, and "
                           + "complete the fix for each, set out in the next finding, before the policy changes.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = $"{domain.Domain} above {HealthyPassRate:0}% for seven consecutive days.",
                });
            }

            // One finding, not one per host.
            //
            // A security gateway is five hostnames, a bulk sender is twelve,
            // and the register printed a row for each: five High rows saying
            // the same sentence about smtp003, smtp005 and cloud-sec-av, all
            // with the same action. A client reads two of those and stops,
            // which loses the ones underneath that were different.
            //
            // Grouped, named, and counted. The names are what somebody has to
            // quote to a vendor, so they are in the finding rather than left
            // to the table above.
            if (InventoryOf(SenderClass.Misconfigured) is { Count: > 0 } broken)
            {
                var atRisk = broken.Sum(s => s.Failing);

                items.Add(new RemediationItem
                {
                    Priority = atRisk >= MaterialMessages ? "High" : "Medium",
                    Finding = $"{Operators(broken)} service(s) sending on your behalf are not set up to prove the mail "
                            + $"is yours: {Name(broken)}. {atRisk:N0} message(s) affected.",
                    Impact = "These are your own messages. They are at risk of being refused under an enforcing "
                           + "policy, and some are already being filed as junk.",
                    Action = broken.All(PassesMailOn)
                        ? "These are security gateways or your own mail platform, and they break the signature as "
                        + "they pass your mail on. Fix it in their settings: have the gateway sign after it scans, "
                        + "or send your outbound mail around it. Changing DNS does not fix this."
                        : broken.Any(PassesMailOn)
                        ? $"Two different fixes. {Name([.. broken.Where(x => !PassesMailOn(x))])}: turn on custom DKIM "
                        + $"signing for {(Domains.Count == 1 ? Domains[0].Domain : "your domain")}, and a custom "
                        + $"return-path (bounce) domain under it if offered. {Name([.. broken.Where(PassesMailOn)])}: "
                        + "validate the outbound mail flow, then set it to preserve DKIM signatures or re-sign as "
                        + "your domain after processing. Adding anything to SPF alone does not fix either."
                        : broken.Any(s => s.Authenticated)
                        // DKIM first. Adding the vendor to SPF authorizes its
                        // servers, but SPF only counts for DMARC when the
                        // return-path domain is also yours - which it is
                        // not, by default, at any bulk sender. Told to "add
                        // it to SPF", a client does, and nothing changes.
                        ? "Each signs as its own domain rather than as yours. Turn on custom DKIM signing for your "
                        + "domain at each vendor. If the vendor also offers a custom return-path (bounce) domain "
                        + "under yours, set that up too. Adding the vendor to SPF alone does not fix this."
                        : "Confirm which systems these are, then authorize them properly rather than leaving them "
                        + "half-configured.",
                    Owner = $"The vendors named, with {(ProviderIsUnnamed ? "your IT provider" : ProviderName)}",
                    Validation = "Seven consecutive days of aligned mail from each.",
                });
            }

            if (InventoryOf(SenderClass.Unidentified) is { Count: > 0 } unknown)
            {
                items.Add(new RemediationItem
                {
                    Priority = "Medium",
                    Finding = $"{unknown.Count} source(s) at providers we recognize sent as you without proving "
                            + $"entitlement: {Name(unknown)}. {unknown.Sum(s => s.Failing):N0} message(s).",
                    Impact = "Usually a tool somebody signed up for and nobody recorded. Until it is confirmed it "
                           + "cannot be told apart from somebody using the same provider to send as you.",
                    Action = "Confirm whether these are yours. If they are, authorize them; if not, they belong in "
                           + "the list below.",
                    Owner = "You, with whoever manages the tools your teams buy",
                    Validation = "Each one is either authorized and aligning, or gone.",
                });
            }

            if (InventoryOf(SenderClass.Suspicious) is { Count: > 0 } strangers)
            {
                var volume = strangers.Sum(s => s.Failing);
                var spread = strangers.Max(s => s.OtherClientsAffected);

                // "Refused" only when the policy actually refuses it. p=reject
                // with sp=none refuses nothing sent as a subdomain, and
                // pct=25 lets three quarters through; both are states two
                // real domains here are in, and both were being called "the
                // protection working".
                var refused = EveryDomainFullyEnforcing;

                items.Add(new RemediationItem
                {
                    Priority = refused ? "Low"
                             : volume >= MaterialMessages ? "High" : "Medium",
                    Finding = $"{strangers.Count} source(s) sent {volume:N0} message(s) as you and never "
                            + $"authenticated once: {Name(strangers)}"
                            + (spread > 0
                                ? $". The busiest was seen against {spread} unrelated organization(s), so this is "
                                + "broad activity rather than somebody targeting you."
                                : "."),
                    Impact = refused
                        ? "Already refused or filed as junk by the receiving provider, because your policy is "
                        + "enforcing. This is the protection working."
                        : EveryDomainEnforcing
                            ? "Not all of it stopped: your policy is enforcing, but a subdomain policy of none or "
                            + "a pct below 100 lets some of this through to inboxes."
                            : "Not currently stopped: your policy asks receivers to do nothing about it.",
                    Action = refused
                        ? "No action needed. Recorded so the pattern is visible if it grows."
                        : EveryDomainEnforcing
                            ? "Close the gap: set sp= to match p=, and take pct to 100."
                            // Not "raise the policy" on its own while the
                            // client's own services still fail: the decision
                            // box says to hold until they pass, and a
                            // register that says both is one the client
                            // stops trusting.
                            : InventoryOf(SenderClass.Misconfigured).Count > 0
                                ? "Once the named services authenticate, raise the policy so receivers are asked to "
                                + "refuse it."
                                : "Raise the policy so receivers are asked to refuse it.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = refused
                        ? "The volume stops, or stays refused."
                        : "The policy is fully enforcing and this mail is being refused.",
                });
            }

            // Only after the mail is right. Told to raise a policy first, an
            // MSP breaks a customer's invoicing and learns not to trust the
            // report.
            // Including the ones that sent nothing this month. A quiet
            // p=none domain is still a domain anybody can send as, and
            // leaving it out of the register let the all-clear print
            // "every domain is enforcing" over it.
            foreach (var domain in Domains.Where(d => d is { IsEnforcing: false, IsStruggling: false }))
            {
                items.Add(new RemediationItem
                {
                    Priority = "Medium",
                    Finding = domain.PolicyKnown
                        ? $"{domain.Domain} is at p={domain.Policy}, so receivers are asked to do nothing "
                          + "about mail that fails."
                        : $"{domain.Domain}'s policy is not known for this period: no receiver has reported "
                          + "on it.",
                    Impact = "Anybody can send mail as this domain today and have it delivered.",
                    Action = domain.Messages == 0
                        ? "Confirm whether this domain sends mail at all. If it does not, publish p=reject "
                        + "and it is closed."
                        : BrokenSendersFor(domain).Count > 0
                            ? "Correct the named services first, then move to p=quarantine."
                        : domain.Readiness == "Ready"
                            ? "Its own mail authenticates. Move to p=quarantine, then to p=reject."
                            : $"Account for the {domain.OwnFailing:N0} failing message(s) first, then move to "
                            + "p=quarantine.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "The policy is published and the domain's own mail keeps arriving.",
                });
            }

            if (InventoryOf(SenderClass.Retired) is { Count: > 0 } gone)
            {
                items.Add(new RemediationItem
                {
                    Priority = "Low",
                    Finding = $"{gone.Count} sender(s) sent as you last period and not at all this one: "
                            + $"{Name(gone)}.",
                    Impact = "Either a service was retired and is still authorized to send as you, or something "
                           + "stopped working quietly.",
                    Action = "Confirm which. If retired, remove it from SPF so the authorization goes with it.",
                    Owner = ProviderIsUnnamed ? "Your IT provider" : ProviderName,
                    Validation = "Either mail resumes, or the authorization is removed.",
                });
            }

            return [.. items.OrderBy(i => i.Rank)];

        }
    }
}
