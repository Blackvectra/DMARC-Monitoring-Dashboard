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
