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
}
