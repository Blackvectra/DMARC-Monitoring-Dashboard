namespace DmarcMonitor.Core.Tls;

/// <summary>
/// An SMTP TLS reporting (TLS-RPT) report, RFC 8460.
///
/// Where DMARC reports say who is allowed to send as you, these say whether
/// the mail reaching you was encrypted in transit and whether anyone failed
/// trying. They are the only routine warning of an active downgrade attack on
/// your inbound mail, and almost nobody reads them.
/// </summary>
public sealed record TlsReport
{
    public required string OrganizationName { get; init; }
    public string ContactInfo { get; init; } = "";
    public required string ReportId { get; init; }

    public DateTimeOffset Begin { get; init; }
    public DateTimeOffset End { get; init; }

    public required IReadOnlyList<TlsPolicyResult> Policies { get; init; }

    public long SuccessfulSessions => Policies.Sum(p => p.SuccessfulSessionCount);
    public long FailedSessions => Policies.Sum(p => p.FailedSessionCount);
    public long TotalSessions => SuccessfulSessions + FailedSessions;

    public bool HasFailures => FailedSessions > 0;

    /// <summary>
    /// Percentage of sessions that negotiated TLS successfully. Zero sessions
    /// reports 0 rather than dividing, because "no mail at all" and "all mail
    /// failed" are different and must not render identically.
    /// </summary>
    public double SuccessRate =>
        TotalSessions == 0 ? 0 : Math.Round(SuccessfulSessions * 100.0 / TotalSessions, 1);
}

public sealed record TlsPolicyResult
{
    public required TlsPolicy Policy { get; init; }
    public long SuccessfulSessionCount { get; init; }
    public long FailedSessionCount { get; init; }
    public IReadOnlyList<TlsFailureDetail> Failures { get; init; } = [];
}

public sealed record TlsPolicy
{
    public TlsPolicyType Type { get; init; } = TlsPolicyType.Unknown;
    public string Domain { get; init; } = "";

    /// <summary>The policy as the receiver fetched it, line by line.</summary>
    public IReadOnlyList<string> PolicyStrings { get; init; } = [];

    /// <summary>
    /// MX hosts the policy covers. Some receivers send this as a single
    /// string rather than an array, and Microsoft omits it entirely.
    /// </summary>
    public IReadOnlyList<string> MxHosts { get; init; } = [];

    /// <summary>
    /// The MTA-STS mode, read out of the policy the receiver actually
    /// fetched rather than whatever DNS says today.
    ///
    /// This is the field that matters and the one nothing surfaces. A policy
    /// in <see cref="MtaStsMode.Testing"/> is not protecting anything: the
    /// receiver reports failures and then delivers over plaintext anyway. A
    /// domain can sit in testing mode for years, generate clean reports, and
    /// be no more protected than one with no policy at all.
    /// </summary>
    public MtaStsMode Mode { get; init; } = MtaStsMode.Unknown;

    /// <summary>True when this policy is actually enforcing TLS.</summary>
    public bool IsEnforcing => Type == TlsPolicyType.Sts && Mode == MtaStsMode.Enforce;
}

public enum TlsPolicyType
{
    Unknown,

    /// <summary>MTA-STS.</summary>
    Sts,

    /// <summary>DANE.</summary>
    Tlsa,

    /// <summary>The sender looked and found no policy.</summary>
    NoPolicyFound,
}

public enum MtaStsMode
{
    Unknown,

    /// <summary>Published but explicitly inactive.</summary>
    None,

    /// <summary>Failures are reported and then ignored. Protects nothing.</summary>
    Testing,

    /// <summary>Failures cause delivery to be refused. The only protective mode.</summary>
    Enforce,
}

public sealed record TlsFailureDetail
{
    public TlsFailureType ResultType { get; init; } = TlsFailureType.Unknown;

    /// <summary>Verbatim result type, so a value RFC 8460 does not define is not lost.</summary>
    public string RawResultType { get; init; } = "";

    public string SendingMtaIp { get; init; } = "";
    public string ReceivingMxHostname { get; init; } = "";
    public string ReceivingMxHelo { get; init; } = "";
    public string ReceivingIp { get; init; } = "";
    public long FailedSessionCount { get; init; }
    public string AdditionalInformation { get; init; } = "";
    public string FailureReasonCode { get; init; } = "";

    /// <summary>
    /// Whether this failure is consistent with an interception attempt rather
    /// than a misconfiguration.
    ///
    /// STARTTLS being stripped, or a certificate that does not match the host
    /// the sender expected, is what an active downgrade looks like from the
    /// sender's side. An expired certificate is somebody forgetting to renew.
    /// Both are worth fixing; only one is worth waking somebody for.
    /// </summary>
    public bool SuggestsInterception => ResultType is
        TlsFailureType.StartTlsNotSupported or
        TlsFailureType.CertificateHostMismatch or
        TlsFailureType.ValidationFailure or
        TlsFailureType.StsWebpkiInvalid;
}

/// <summary>RFC 8460 §4.3 result types, plus Unknown so an unlisted value does not fail the parse.</summary>
public enum TlsFailureType
{
    Unknown,
    StartTlsNotSupported,
    CertificateHostMismatch,
    CertificateExpired,
    CertificateNotTrusted,
    ValidationFailure,
    TlsaInvalid,
    DnssecInvalid,
    DaneRequired,
    StsPolicyFetchError,
    StsPolicyInvalid,
    StsWebpkiInvalid,
}
