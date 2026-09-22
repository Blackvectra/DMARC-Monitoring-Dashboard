using DmarcMonitor.Core.Tls;
using Xunit;

namespace DmarcMonitor.Core.Tests.Tls;

/// <summary>
/// Two pages disagreeing about the same domain on the same morning.
///
/// The TLS reports page read the mode out of the reports and raised "2
/// domain(s) in testing mode, which protects nothing" against ndaco.org and
/// nrgtechservices.com. The domains table, reading the policy those domains
/// actually serve, showed both enforcing. Checked against the live files:
/// both really are at <c>mode: enforce</c>, and the reports were from the two
/// days before the change.
///
/// Neither source was broken. A TLS report says what the SENDER had, and a
/// sender caches an MTA-STS policy for its max_age - 604800 seconds, a full
/// week, on nrgtechservices.com. So for a week after moving a domain to
/// enforce, every report still says testing, and a page that believes them
/// tells an operator their protected domain protects nothing.
/// </summary>
public sealed class PolicyModeLagTests
{
    private static TlsDomainSummary Domain(string reported, string served = "") => new()
    {
        Domain = "nrgtechservices.com",
        ClientName = "NRG TechServices",
        ClientSlug = "nrg-techservices",
        Successful = 46,
        ReportedMode = reported,
        ServedMode = served,
    };

    [Fact]
    public void WhatTheDomainServesNowWins()
    {
        // The real case, to the day.
        var domain = Domain(reported: "testing", served: "enforce");

        Assert.Equal("enforce", domain.PolicyMode);
        Assert.True(domain.IsProtected);
    }

    [Fact]
    public void AndTheLagIsSaidOutLoudRatherThanHidden()
    {
        // The figures on the row were gathered under the previous policy.
        // Silently showing them beside the new mode is the other way to be
        // confusing.
        Assert.True(Domain(reported: "testing", served: "enforce").ModeChangedSinceReports);
        Assert.False(Domain(reported: "enforce", served: "enforce").ModeChangedSinceReports);
    }

    /// <summary>
    /// A domain really in testing is still called out.
    /// </summary>
    /// <remarks>
    /// The fix must not turn the warning off. dmvwrr.com serves
    /// <c>mode: testing</c> today, and a policy in testing has its failures
    /// reported and its mail delivered over plaintext anyway.
    /// </remarks>
    [Fact]
    public void ADomainThatReallyIsInTestingIsStillCalledOut()
    {
        var domain = Domain(reported: "testing", served: "testing") with { Domain = "dmvwrr.com" };

        Assert.Equal("testing", domain.PolicyMode);
        Assert.False(domain.IsProtected);
        Assert.False(domain.ModeChangedSinceReports);
    }

    /// <summary>
    /// With no DNS reading, the reports are the only evidence there is.
    /// </summary>
    /// <remarks>
    /// A scan that has never run must not make every domain read as unknown.
    /// This is the state a fresh install is in for its first night.
    /// </remarks>
    [Fact]
    public void WithNoScanTheReportsAreStillBelieved()
    {
        var domain = Domain(reported: "testing");

        Assert.Equal("testing", domain.PolicyMode);
        Assert.False(domain.ModeChangedSinceReports);
    }

    /// <summary>
    /// Enforcing and failing is still the one urgent state.
    /// </summary>
    [Fact]
    public void EnforcingAndLosingMailIsUnaffected()
    {
        var domain = Domain(reported: "testing", served: "enforce") with { Failed = 3 };

        Assert.True(domain.IsLosingMail);
        Assert.False(domain.IsProtected);
    }
}

/// <summary>
/// A mode nobody has verified is not a finding.
///
/// The earlier fix made the served policy win where one had been read. It
/// left the ordinary case alone: on an install that has not scanned DNS -
/// which is every install until the nightly job first runs, and every copy of
/// the trial download - there is no served mode, so the page fell back to
/// what senders had cached and stated it as fact.
///
/// That put a domain serving enforce with a seven-day max_age under "in
/// testing mode, which protects nothing".
/// </summary>
public sealed class UnverifiedModeTests
{
    private static TlsDomainSummary Domain(string reported, string served = "") =>
        new()
        {
            Domain = "nrgtechservices.com",
            ClientName = "NRG Tech Services",
            ClientSlug = "nrg-tech-services",
            ReportedMode = reported,
            ServedMode = served,
        };

    [Fact]
    public void AModeFromReportsAloneIsNotVerified()
    {
        var cached = Domain(reported: "testing");

        Assert.False(cached.ModeVerified);

        // Still shown - it is the only reading there is - but as what it is.
        Assert.Equal("testing", cached.PolicyMode);
    }

    [Fact]
    public void AModeFromTheServedPolicyIsVerified()
    {
        var read = Domain(reported: "testing", served: "enforce");

        Assert.True(read.ModeVerified);
        Assert.Equal("enforce", read.PolicyMode);
        Assert.True(read.ModeChangedSinceReports);
    }

    [Fact]
    public void ReadingItAndFindingTestingIsStillVerified()
    {
        var read = Domain(reported: "testing", served: "testing");

        Assert.True(read.ModeVerified);
        Assert.Equal("testing", read.PolicyMode);

        // Nothing changed, so there is nothing to explain away.
        Assert.False(read.ModeChangedSinceReports);
    }
}
