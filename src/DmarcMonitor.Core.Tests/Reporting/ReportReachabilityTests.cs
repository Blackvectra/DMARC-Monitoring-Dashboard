using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Whether a domain's reports can actually get back to the collector.
///
/// Both ways this breaks are silent, which is the whole reason it needs a
/// check. A receiver that looks for the RFC 7489 §7.1 authorization record and
/// does not find it declines to send and tells nobody, so a broken customer
/// looks exactly like a quiet one. And a domain whose rua points at a mailbox
/// nothing collects has perfect DNS and produces nothing.
///
/// Three of sixteen real domains were broken the first way and one was broken
/// the second, and all four were found by hand. They are all fixed now, so the
/// only thing keeping this honest is what is written down here.
/// </summary>
public sealed class ReportReachabilityTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 21, 12, 0, 0, TimeSpan.Zero);

    private static DomainReachability Domain(
        string name = "acme.com",
        string? rua = "mailto:dmarc@msp.example",
        string policy = "none",
        Dictionary<string, string?>? authorizations = null,
        int reportsHeld = 12,
        int lastReportDaysAgo = 1,
        int organizationsHolding = 1,
        bool dnsFailed = false) => new()
        {
            Domain = name,
            Destinations = ReportReachability.Destinations(rua, name),
            Policy = policy,
            Authorizations = authorizations
                ?? new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                {
                    [$"{name}._report._dmarc.msp.example"] = "v=DMARC1",
                },
            ReportsHeld = reportsHeld,
            OrganizationsHolding = organizationsHolding,
            LastReport = reportsHeld == 0 ? null : Now.AddDays(-lastReportDaysAgo),
            DnsFailed = dnsFailed,
        };

    // ---- reading the rua tag --------------------------------------------------

    [Fact]
    public void ARuaInsideTheDomainsOwnOrganizationNeedsNoAuthorization()
    {
        // RFC 7489 §7.1 is about one domain accepting reports on another's
        // behalf. A domain reporting to itself is not that.
        var destination = Assert.Single(
            ReportReachability.Destinations("mailto:dmarc@acme.com", "acme.com"));

        Assert.False(destination.External);
    }

    [Fact]
    public void ASubdomainOfTheReportingDomainIsStillInternal()
    {
        var destination = Assert.Single(
            ReportReachability.Destinations("mailto:d@rua.acme.com", "acme.com"));

        Assert.False(destination.External);
    }

    [Fact]
    public void AMailboxInSomebodyElsesDomainIsExternal()
    {
        var destination = Assert.Single(
            ReportReachability.Destinations("mailto:dmarc@msp.example", "acme.com"));

        Assert.True(destination.External);
        Assert.Equal("msp.example", destination.Domain);
        Assert.Equal("acme.com._report._dmarc.msp.example", destination.AuthorizationName("acme.com"));
    }

    [Fact]
    public void ASizeLimitIsPartOfTheUriAndNotPartOfTheDomain()
    {
        // mailto:d@example.com!10m is legal. Keeping the suffix would look for
        // an authorization record under "example.com!10m", which nobody can
        // publish, and report every such domain as unauthorized.
        var destination = Assert.Single(
            ReportReachability.Destinations("mailto:dmarc@msp.example!10m", "acme.com"));

        Assert.Equal("dmarc@msp.example", destination.Address);
        Assert.Equal("msp.example", destination.Domain);
    }

    [Fact]
    public void SeveralDestinationsAreAllRead()
    {
        var found = ReportReachability.Destinations(
            "mailto:dmarc@msp.example, mailto:qinvzy2f@ag.us.vendor.example", "acme.com");

        Assert.Equal(2, found.Count);
        Assert.All(found, d => Assert.True(d.External));
    }

    [Theory]
    [InlineData("https://example.com/dmarc")]
    [InlineData("mailto:not-an-address")]
    [InlineData("mailto:@example.com")]
    [InlineData("")]
    public void AnythingThisCannotReasonAboutIsSkippedRatherThanGuessedAt(string rua)
    {
        Assert.Empty(ReportReachability.Destinations(rua, "acme.com"));
    }

    // ---- the authorization record ----------------------------------------------

    [Fact]
    public void AMissingAuthorizationIsBreakingAndSaysNobodyIsTold()
    {
        // The silent failure. Three real domains were in this state and the
        // only symptom was a customer that produced no data.
        var findings = ReportReachability.Assess(
            Domain(authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = "",
            }),
            Now);

        var f = Assert.Single(findings, x => x.Reference.StartsWith("RFC 7489 §7.1", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("silently does not send", f.Problem, StringComparison.Ordinal);
        Assert.Contains("acme.com._report._dmarc.msp.example", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAuthorizationSpelledInLowerCaseAuthorizesNothing()
    {
        // RFC 7489 writes the version out character by character, so it is
        // case sensitive. One real record was published this way.
        var findings = ReportReachability.Assess(
            Domain(authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = "v=dmarc1;",
            }),
            Now);

        var f = Assert.Single(findings, x => x.Reference.StartsWith("RFC 7489 §7.1", StringComparison.Ordinal));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("DMARC1 in capitals", f.Problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("v=DMARC1")]
    [InlineData("v=DMARC1;")]
    [InlineData("V=DMARC1; rua=mailto:x@msp.example")]
    public void AWellFormedAuthorizationProducesNothing(string record)
    {
        var findings = ReportReachability.Assess(
            Domain(authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = record,
            }),
            Now);

        Assert.Empty(findings);
    }

    [Fact]
    public void AnAuthorizationLookupThatFailedConcludesNothing()
    {
        // Null is not absence. Reporting it as a missing record would have
        // somebody publish one that is already there.
        var findings = ReportReachability.Assess(
            Domain(authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = null,
            }),
            Now);

        var f = Assert.Single(findings);

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("could not be read", f.Problem, StringComparison.Ordinal);
    }

    // ---- reports actually arriving ------------------------------------------------

    [Fact]
    public void ADomainWhoseReportsGoSomewhereNobodyCollectsIsBreaking()
    {
        // One real domain sits exactly here: p=reject, strict on both
        // mechanisms, rua pointing at a mailbox nothing reads, and not one
        // report ever.
        var findings = ReportReachability.Assess(
            Domain(rua: "mailto:support@acme.com", policy: "reject", reportsHeld: 0), Now);

        var f = Assert.Single(findings);

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("not one has ever arrived here", f.Problem, StringComparison.Ordinal);
        Assert.Contains("Point the collector at that mailbox", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AtRejectTheSilenceIsSaidToCostMail()
    {
        // A monitoring gap at p=none and mail being lost unwatched at
        // p=reject should not read the same.
        var atReject = ReportReachability.Assess(
            Domain(rua: "mailto:support@acme.com", policy: "reject", reportsHeld: 0), Now);
        var atNone = ReportReachability.Assess(
            Domain(rua: "mailto:support@acme.com", policy: "none", reportsHeld: 0), Now);

        Assert.Contains("mail is being lost", Assert.Single(atReject).Problem, StringComparison.Ordinal);
        Assert.DoesNotContain("mail is being lost", Assert.Single(atNone).Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void NoReportsWithAMissingAuthorizationBlamesTheAuthorization()
    {
        // Two findings that are really one fault. Saying "point the collector
        // at that mailbox" when the real problem is a missing record sends an
        // operator to the wrong place.
        var findings = ReportReachability.Assess(
            Domain(reportsHeld: 0, authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = "",
            }),
            Now);

        var arriving = Assert.Single(findings, f => f.Problem.Contains("ever arrived", StringComparison.Ordinal));

        Assert.Contains("missing authorization above is the likely reason", arriving.Problem, StringComparison.Ordinal);
        Assert.Contains("Publish the authorization record", arriving.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAuthorizationLookupThatFailedIsNotBlamedForTheSilence()
    {
        // Two findings that must not be welded together. When the
        // authorization record could not be READ, nothing is known about it -
        // so telling the operator that a missing authorization is why no
        // reports arrive, and to go and publish one, is a claim on no
        // evidence and sends them to fix something that may be correct.
        var findings = ReportReachability.Assess(
            Domain(reportsHeld: 0, authorizations: new(StringComparer.OrdinalIgnoreCase)
            {
                ["acme.com._report._dmarc.msp.example"] = null,
            }),
            Now);

        var arriving = Assert.Single(findings, f => f.Problem.Contains("ever arrived", StringComparison.Ordinal));

        Assert.DoesNotContain("missing authorization", arriving.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain("Publish the authorization record", arriving.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainThatUsedToReportAndHasGoneQuietIsAWeakness()
    {
        var findings = ReportReachability.Assess(Domain(lastReportDaysAgo: 21), Now);

        var f = Assert.Single(findings);

        Assert.Equal(HygieneSeverity.Weakness, f.Severity);
        Assert.Contains("21 days", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrdinaryGapBetweenReportsIsNotAFinding()
    {
        // Receivers send daily but not all of them every day, and a weekend is
        // not a fault.
        Assert.Empty(ReportReachability.Assess(Domain(lastReportDaysAgo: 3), Now));
    }

    // ---- the basics ------------------------------------------------------------------

    [Fact]
    public void NoRuaAtAllIsTheMostBasicWayForThisToBeBroken()
    {
        var f = Assert.Single(ReportReachability.Assess(Domain(rua: null, reportsHeld: 0), Now));

        Assert.Equal(HygieneSeverity.Breaking, f.Severity);
        Assert.Contains("publishes no rua address", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainWhoseDnsCouldNotBeReadIsNotJudged()
    {
        var f = Assert.Single(ReportReachability.Assess(Domain(dnsFailed: true), Now));

        Assert.Contains("could not be read", f.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain("publishes no rua", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainReportingCleanlyProducesNothing()
    {
        Assert.Empty(ReportReachability.Assess(Domain(), Now));
    }

    // ---- the same name in two organizations -----------------------------------
    //
    // Domains used to be resolved by name across the whole install, so a
    // collector run under the wrong --org still filed correctly. Now that each
    // organization holds its own row, the same typo makes a second copy instead
    // - and that is silent: the customer's real domain simply stops growing,
    // and an operator reads it as a quiet month. This is the finding that makes
    // it visible.

    [Fact]
    public void ADomainHeldByTwoOrganizationsIsPointedAtRatherThanJudged()
    {
        // Two MSPs each looking after example.com for their own customer is
        // legitimate - it is why the schema says UNIQUE(tenant_id, name).
        // Nothing here can tell that apart from a mistyped --org, so it reports
        // and does not instruct. The confident version of this would be telling
        // somebody to delete another customer's domain.
        var f = Assert.Single(ReportReachability.Assess(Domain(organizationsHolding: 2), Now));

        Assert.Equal(HygieneSeverity.Tidy, f.Severity);
        Assert.Contains("2 organizations", f.Problem, StringComparison.Ordinal);
        Assert.Contains("--org", f.Problem, StringComparison.Ordinal);
        Assert.Contains("Check both are meant to exist", f.Fix, StringComparison.Ordinal);
    }

    [Fact]
    public void OneOrganizationHoldingItSaysNothing()
    {
        Assert.Empty(ReportReachability.Assess(Domain(organizationsHolding: 1), Now));
    }

    [Fact]
    public void TheDuplicateIsStillReportedOnADomainThatIsAlsoBroken()
    {
        // It is raised before the no-rua case returns early, because a domain
        // duplicated by a typo is very likely also the one with nothing
        // arriving - and finding out about the second copy only after fixing
        // the first would be two trips.
        var findings = ReportReachability.Assess(Domain(rua: null, organizationsHolding: 2), Now);

        Assert.Contains(findings, f => f.Problem.Contains("2 organizations", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Problem.Contains("publishes no rua", StringComparison.Ordinal));
    }

    [Fact]
    public void ADomainWhoseDnsFailedSaysOnlyThat()
    {
        // A failed lookup establishes nothing, and stacking a second finding on
        // top of "we could not read it" is a sentence about something nobody
        // checked.
        var f = Assert.Single(
            ReportReachability.Assess(Domain(dnsFailed: true, organizationsHolding: 2), Now));

        Assert.Contains("could not be read", f.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void NullsAreRefused()
    {
        Assert.Throws<ArgumentNullException>(() => ReportReachability.Assess(null!, Now));
        Assert.Throws<ArgumentException>(() => ReportReachability.Destinations("mailto:a@b.example", ""));
    }
}
