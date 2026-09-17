using System.Globalization;

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
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    public IReadOnlyList<ReportDomainHealth> Domains { get; init; } = [];
    public IReadOnlyList<ReportSource> Sources { get; init; } = [];
    public IReadOnlyList<ReportChange> Changes { get; init; } = [];

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing { get; init; }

    public long PreviousMessages { get; init; }
    public long PreviousPassing { get; init; }

    public double PassRate => Messages == 0 ? 0 : Math.Round(Passing * 100.0 / Messages, 1);

    public double PreviousPassRate =>
        PreviousMessages == 0 ? 0 : Math.Round(PreviousPassing * 100.0 / PreviousMessages, 1);

    /// <summary>True when there is a previous period to compare against at all.</summary>
    public bool HasComparison => PreviousMessages > 0;

    /// <summary>Sources sending legitimately, whether or not they are aligned.</summary>
    public IReadOnlyList<ReportSource> LegitimateSources =>
        [.. Sources.Where(s => s.IsClean || s.Authenticated).OrderByDescending(s => s.Messages)];

    /// <summary>
    /// Sources that authenticated nothing at all. Either a service nobody
    /// recorded, or somebody sending as the client.
    /// </summary>
    public IReadOnlyList<ReportSource> ImpersonatingSources =>
        [.. Sources.Where(s => !s.IsClean && !s.Authenticated).OrderByDescending(s => s.Failing)];

    /// <summary>Sources that are real services set up unaligned, so mail of theirs is being lost.</summary>
    public IReadOnlyList<ReportSource> MisconfiguredSources =>
        [.. Sources.Where(s => !s.IsClean && s.Authenticated).OrderByDescending(s => s.Failing)];

    /// <summary>
    /// The number that answers "what am I paying for". Messages that failed
    /// authentication while a policy was in force to act on them.
    /// </summary>
    public long MessagesActedOn =>
        Domains.Where(d => d.IsEnforcing).Sum(d => d.Messages - d.Passing);

    public bool EveryDomainEnforcing => Domains.Count > 0 && Domains.All(d => d.IsEnforcing);
}
