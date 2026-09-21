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
    public required string ClientName { get; init; }
    public required string ProviderName { get; init; }
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
            .Select(g => new ReportSender
            {
                Name = g.Key,
                IsService = SenderCatalog.Identify(g.First().SourceIp) is not null,
                Addresses = g.Count(),
                Messages = g.Sum(s => s.Messages),
                Domains = [.. g.SelectMany(s => s.Domains).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal)],
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
}
