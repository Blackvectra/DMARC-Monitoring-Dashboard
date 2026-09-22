namespace DmarcMonitor.Core.Forensic;

/// <summary>
/// One DMARC failure report: RFC 6591, carried as RFC 5965 feedback.
///
/// The third report type, and the only one that is about a single message
/// rather than a count. An aggregate report says "1,400 messages from
/// 192.0.2.1 failed DMARC last Tuesday"; this says "here is one of them, sent
/// at 09:14, from this envelope, with this subject, and here is what the
/// receiver checked". It is what answers "show me one" when somebody disputes
/// a finding, and it is the only place a Subject line ever appears in this
/// product.
///
/// WHAT MAKES THESE DIFFERENT TO HANDLE
///
/// Everything else here is statistics. This is correspondence. A failure
/// report carries the envelope and headers of a real message - who it claimed
/// to be from, who it was going to, and what it was about - which is personal
/// data of a kind aggregate reports never contain. That is why the retention
/// window for them is separate and shorter, why the reported headers are
/// stored apart from the summary, and why reading them is gated rather than
/// being one more table anybody signed in can browse.
///
/// WHY THERE WILL NOT BE MANY
///
/// Almost no large receiver sends them. Publishing ruf= gets reports from a
/// handful of providers and silence from Google, Microsoft and Yahoo, because
/// forwarding a customer's mail to a third party is a privacy problem for the
/// receiver too. So an estate with ruf= on every domain can quite correctly
/// show nothing here for weeks, and the page has to say that rather than
/// looking broken.
/// </summary>
public sealed record ForensicReport
{
    /// <summary>The domain the report is about, from Reported-Domain or the From header.</summary>
    public required string Domain { get; init; }

    /// <summary>When the receiver says the message arrived.</summary>
    public DateTimeOffset? ArrivalDate { get; init; }

    /// <summary>The address the message really came from, as SMTP saw it.</summary>
    public string SourceIp { get; init; } = "";

    /// <summary>The SMTP envelope sender: Original-Mail-From, the return path.</summary>
    public string ReturnPath { get; init; } = "";

    /// <summary>The From: header of the reported message - what the reader would have seen.</summary>
    public string HeaderFrom { get; init; } = "";

    /// <summary>The reported message's Subject.</summary>
    public string Subject { get; init; } = "";

    /// <summary>The reported message's Message-ID, which is how a sender finds it in their own logs.</summary>
    public string MessageId { get; init; } = "";

    /// <summary>pass, fail, none - as the receiver's Authentication-Results said.</summary>
    public string DkimResult { get; init; } = "";

    public string SpfResult { get; init; } = "";

    /// <summary>The d= domain of the DKIM signature, when one was present.</summary>
    public string DkimDomain { get; init; } = "";

    /// <summary>What failed: dmarc, spf, dkim, or empty when the report did not say.</summary>
    public string AuthFailureType { get; init; } = "";

    /// <summary>
    /// What the receiver did with it: reject, quarantine, delivered, none.
    /// </summary>
    /// <remarks>
    /// Worth more than it looks. A report of a message that was delivered
    /// anyway is a domain at p=none watching a forgery land in somebody's
    /// inbox; the same report with reject is the policy working. The two read
    /// identically without this.
    /// </remarks>
    public string DeliveryResult { get; init; } = "";

    /// <summary>Who sent the report: the User-Agent of the reporting receiver.</summary>
    public string ReportedBy { get; init; } = "";

    /// <summary>
    /// The reported message's headers, and only its headers.
    /// </summary>
    /// <remarks>
    /// The body is dropped at the parser, never stored and never offered. A
    /// failure report may legitimately carry the whole original message, and
    /// keeping somebody's correspondence on an MSP's server for thirty days
    /// is not a thing to do by accident because a receiver was generous.
    /// Headers alone answer every question this feature exists for.
    /// </remarks>
    public string ReportedHeaders { get; init; } = "";

    /// <summary>
    /// True when the message was delivered despite failing.
    /// </summary>
    /// <remarks>
    /// The worst outcome and the one to rank first: a forgery that failed
    /// authentication and reached a person anyway. Empty and "none" both read
    /// as delivered, because a receiver that did not say what it did with a
    /// failing message did not quarantine it.
    /// </remarks>
    public bool WasDelivered =>
        DeliveryResult.Length == 0
        || DeliveryResult.Equals("none", StringComparison.OrdinalIgnoreCase)
        || DeliveryResult.Equals("delivered", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The outcome of parsing one failure report.
/// </summary>
/// <remarks>
/// The same contract the other two parsers hold to: tolerant of shape, never
/// of meaning. A report that cannot be read is a failure with a reason, never
/// an empty success - "nothing failed" and "this did not parse" must not
/// render identically to an operator.
/// </remarks>
public sealed record ForensicParseResult
{
    public bool Success { get; private init; }

    public ForensicReport? Report { get; private init; }

    /// <summary>Why it could not be read. Empty on success, never null.</summary>
    public string Error { get; private init; } = "";

    public static ForensicParseResult Succeeded(ForensicReport report) =>
        new() { Success = true, Report = report };

    public static ForensicParseResult Failed(string error) =>
        new() { Success = false, Error = error };
}
