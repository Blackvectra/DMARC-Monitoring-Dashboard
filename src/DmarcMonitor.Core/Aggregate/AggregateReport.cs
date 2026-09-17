namespace DmarcMonitor.Core.Aggregate;

/// <summary>
/// One DMARC aggregate report: a single receiver's view of a single domain
/// over a single window. Never the whole picture of a domain's mail, which is
/// the most common way these are misread.
/// </summary>
public sealed record AggregateReport
{
    public required ReportMetadata Metadata { get; init; }
    public required PolicyPublished Policy { get; init; }
    public required IReadOnlyList<ReportRecord> Records { get; init; }

    /// <summary>Total messages, summing each row's count rather than counting rows.</summary>
    public long TotalMessages => Records.Sum(r => (long)r.Count);

    public long PassingMessages => Records.Where(r => r.IsDmarcPass).Sum(r => (long)r.Count);
    public long FailingMessages => TotalMessages - PassingMessages;
}

public sealed record ReportMetadata
{
    public required string OrgName { get; init; }
    public string Email { get; init; } = "";
    public required string ReportId { get; init; }

    /// <summary>Start of the window. DMARC carries these as Unix epoch seconds.</summary>
    public DateTimeOffset Begin { get; init; }
    public DateTimeOffset End { get; init; }
}

/// <summary>The policy the domain owner had published when the report was generated.</summary>
public sealed record PolicyPublished
{
    public required string Domain { get; init; }

    public DmarcPolicy P { get; init; } = DmarcPolicy.None;

    /// <summary>
    /// Subdomain policy. Absent means subdomains inherit p, which is not the
    /// same as an explicit sp=none, so the distinction is kept.
    /// </summary>
    public DmarcPolicy? Sp { get; init; }

    /// <summary>Percentage of mail the policy applies to. Absent means 100.</summary>
    public int Pct { get; init; } = 100;

    public AlignmentMode Adkim { get; init; } = AlignmentMode.Relaxed;
    public AlignmentMode Aspf { get; init; } = AlignmentMode.Relaxed;
}

public enum DmarcPolicy { None, Quarantine, Reject }

public enum AlignmentMode { Relaxed, Strict }

/// <summary>What the receiver did with a message, as opposed to what it concluded.</summary>
public enum Disposition { None, Quarantine, Reject }

/// <summary>A DMARC alignment result for one authentication method.</summary>
public enum DmarcResult { Pass, Fail }

/// <summary>One row: all messages from one source IP that were treated identically.</summary>
public sealed record ReportRecord
{
    public required string SourceIp { get; init; }

    /// <summary>
    /// How many messages this row represents. Routinely thousands, which is
    /// why counting rows instead of summing this understates large senders.
    /// </summary>
    public int Count { get; init; }

    public Disposition Disposition { get; init; } = Disposition.None;

    /// <summary>DKIM ALIGNMENT, not whether a signature verified.</summary>
    public DmarcResult Dkim { get; init; } = DmarcResult.Fail;

    /// <summary>SPF ALIGNMENT, not whether SPF itself passed.</summary>
    public DmarcResult Spf { get; init; } = DmarcResult.Fail;

    /// <summary>Why the receiver chose not to apply the policy, if it did so.</summary>
    public IReadOnlyList<PolicyOverride> Overrides { get; init; } = [];

    /// <summary>The domain the recipient actually sees.</summary>
    public string HeaderFrom { get; init; } = "";

    public string EnvelopeFrom { get; init; } = "";
    public string EnvelopeTo { get; init; } = "";

    /// <summary>
    /// The raw authentication results, which are NOT the same as the alignment
    /// results above. SPF can pass here for bounce.sendgrid.net while Spf
    /// above is Fail, because DMARC only counts authentication that matches
    /// the visible From domain. That gap is the single most misunderstood
    /// thing in a DMARC report.
    /// </summary>
    public IReadOnlyList<AuthResult> SpfResults { get; init; } = [];
    public IReadOnlyList<AuthResult> DkimResults { get; init; } = [];

    /// <summary>DMARC passes when EITHER method passes and aligns.</summary>
    public bool IsDmarcPass => Dkim == DmarcResult.Pass || Spf == DmarcResult.Pass;

    /// <summary>
    /// True when the receiver declined to apply the policy. The authentication
    /// failure is real but is usually a mailing list or forwarder rather than
    /// anything the domain owner should act on.
    /// </summary>
    public bool WasOverridden => Overrides.Count > 0;
}

public sealed record PolicyOverride
{
    public required OverrideReason Type { get; init; }
    public string Comment { get; init; } = "";
}

/// <summary>
/// RFC 7489 §7.2 override types, plus Unknown so a receiver inventing its own
/// value does not fail the parse.
/// </summary>
public enum OverrideReason
{
    Unknown,
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other
}

/// <summary>One raw authentication result, with the domain it authenticated FOR.</summary>
public sealed record AuthResult
{
    public required string Domain { get; init; }

    /// <summary>Raw result verbatim: pass, fail, softfail, neutral, none, temperror, permerror.</summary>
    public required string Result { get; init; }

    /// <summary>DKIM only: the selector that signed.</summary>
    public string Selector { get; init; } = "";

    public bool IsPass => string.Equals(Result, "pass", StringComparison.OrdinalIgnoreCase);
}
