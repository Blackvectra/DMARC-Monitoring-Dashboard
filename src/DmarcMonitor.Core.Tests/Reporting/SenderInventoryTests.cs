using DmarcMonitor.Core.Reporting;
using Xunit;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// What a source IS, for the table a client is asked to confirm.
///
/// A list of addresses and percentages is data. "These four are yours and
/// correct, this one is yours and broken, these two nobody can account for"
/// is the thing somebody can act on, and it is the difference between this
/// and a report parser.
///
/// Every boundary below is drawn to avoid one specific wrong accusation, and
/// the tests are mostly about the accusation rather than the category.
/// </summary>
public sealed class SenderInventoryTests
{
    private static ReportSource Source(
        string ip = "203.0.113.9", long messages = 100, long passing = 100,
        string authenticatedFor = "", bool retired = false, int otherClients = 0) =>
        new()
        {
            SourceIp = ip,
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            AuthenticatedFor = authenticatedFor,
            Retired = retired,
            OtherClientsAffected = otherClients,
        };

    [Fact]
    public void CleanMailIsApproved()
    {
        Assert.Equal(SenderClass.Approved, ClientReport.ClassOf(Source()));
    }

    /// <summary>
    /// The one that matters most: a source that has EVER passed for this
    /// client is the client's own mail path, whatever a particular failing
    /// row looks like.
    /// </summary>
    /// <remarks>
    /// A gateway carrying a customer's outbound breaks a share of its own
    /// signatures in transit. Judged row by row it reads as an intruder, and
    /// it was printed as one: DMV WRR's August report said 177 messages were
    /// "sent by someone who is not you" about the customer's own relay.
    /// Passing even once is the thing a forger cannot do.
    /// </remarks>
    [Fact]
    public void ASourceThatPassesSometimesIsBrokenRatherThanHostile()
    {
        var gateway = Source(messages: 200, passing: 120);

        Assert.Equal(SenderClass.Misconfigured, ClientReport.ClassOf(gateway));
    }

    /// <summary>
    /// A service that never aligns but signs as ITSELF is also the client's
    /// own mail: it is a vendor sending on their behalf, configured badly.
    /// </summary>
    [Fact]
    public void AServiceSigningAsItselfIsMisconfiguredNotUnknown()
    {
        var vendor = Source(messages: 50, passing: 0, authenticatedFor: "sendgrid.net");

        Assert.Equal(SenderClass.Misconfigured, ClientReport.ClassOf(vendor));
    }

    /// <summary>
    /// Never authenticated, and nothing recognises the operator. This is the
    /// only bucket that reads as an accusation, so it is the narrowest.
    /// </summary>
    [Fact]
    public void AnUnprovenSourceNobodyRecognisesIsSuspicious()
    {
        // Documentation range, in no catalog.
        var stranger = Source(ip: "198.51.100.77", messages: 40, passing: 0);

        Assert.Equal(SenderClass.Suspicious, ClientReport.ClassOf(stranger));
    }

    /// <summary>
    /// A recognised operator is not innocence - a shared ESP is where an
    /// unauthorised sender hides most comfortably - it is the difference
    /// between a question for the customer and an alarm.
    /// </summary>
    [Fact]
    public void AnUnprovenSourceAtAKnownProviderIsAQuestionRatherThanAnAlarm()
    {
        // One of Google's published ranges, which the catalog knows.
        var esp = Source(ip: "209.85.128.1", messages: 30, passing: 0);

        Assert.Equal(SenderClass.Unidentified, ClientReport.ClassOf(esp));
    }

    [Fact]
    public void ASourceThatStoppedSendingIsRetired()
    {
        var gone = Source(messages: 0, passing: 0, retired: true);

        Assert.Equal(SenderClass.Retired, ClientReport.ClassOf(gone));
    }

    /// <summary>
    /// A retired source has no mail in the period, so it must not turn up in
    /// the list of what sends the client's mail - where zero failures would
    /// otherwise read as "clean".
    /// </summary>
    [Fact]
    public void RetiredSourcesStayOutOfTheLegitimateList()
    {
        var report = Report(Source(), Source(ip: "203.0.113.50", messages: 0, passing: 0, retired: true));

        var legitimate = Assert.Single(report.LegitimateSources);
        Assert.Equal("203.0.113.9", legitimate.SourceIp);
    }

    [Fact]
    public void TheInventoryPutsEverySourceUnderExactlyOneHeading()
    {
        var report = Report(
            Source(),
            Source(ip: "203.0.113.10", messages: 200, passing: 120),
            Source(ip: "198.51.100.77", messages: 40, passing: 0),
            Source(ip: "203.0.113.50", messages: 0, passing: 0, retired: true));

        var total = report.Inventory.Sum(g => g.Count());

        Assert.Equal(report.Sources.Count, total);
        Assert.Single(report.InventoryOf(SenderClass.Approved));
        Assert.Single(report.InventoryOf(SenderClass.Misconfigured));
        Assert.Single(report.InventoryOf(SenderClass.Suspicious));
        Assert.Single(report.InventoryOf(SenderClass.Retired));
    }

    [Fact]
    public void ANullSourceIsRefusedRatherThanClassified()
    {
        Assert.Throws<ArgumentNullException>(() => ClientReport.ClassOf(null!));
    }

    // ---- why mail failed ----------------------------------------------------

    [Fact]
    public void FailuresAreSplitByCauseRatherThanCountedAsOneRedTotal()
    {
        var report = Report(new ReportSource
        {
            SourceIp = "203.0.113.9",
            Messages = 300,
            Passing = 0,
            Failing = 300,
            FailedSpfNotAligned = 200,
            FailedDkimNotAligned = 80,
            FailedBoth = 20,
        }) with { OverriddenMessages = 15 };

        var causes = report.FailureCauses.ToDictionary(c => c.Cause, c => c.Messages, StringComparer.Ordinal);

        Assert.Equal(200, causes["SPF passed, did not align"]);
        Assert.Equal(80, causes["DKIM verified, did not align"]);
        Assert.Equal(20, causes["Neither check passed"]);
        Assert.Equal(15, causes["Handled by the receiver"]);
    }

    [Fact]
    public void ACauseWithNothingInItIsNotPrinted()
    {
        var report = Report(new ReportSource
        {
            SourceIp = "203.0.113.9",
            Messages = 10,
            Passing = 0,
            Failing = 10,
            FailedBoth = 10,
        });

        Assert.Single(report.FailureCauses);
        Assert.Equal("Neither check passed", report.FailureCauses[0].Cause);
    }

    private static ClientReport Report(params ReportSource[] sources) =>
        new()
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Sources = sources,
        };
}

/// <summary>
/// Whether a domain's policy could safely be raised, and what to do about it.
///
/// The question every one of these reports is really asked, and the one most
/// tools answer with a percentage and leave to the reader.
/// </summary>
public sealed class EnforcementReadinessTests
{
    private static ReportDomainHealth Domain(
        string name = "acme.example", string policy = "none",
        long messages = 1000, long passing = 1000) =>
        new() { Domain = name, Policy = policy, Messages = messages, Passing = passing };

    [Fact]
    public void CleanMailAtPNoneIsReady()
    {
        var domain = Domain();

        Assert.Equal("Ready", domain.Readiness);
        Assert.Contains("can be raised", domain.ReadinessReason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainLosingItsOwnMailIsNotReadyAtAll()
    {
        var domain = Domain(messages: 1000, passing: 500);

        Assert.Equal("Not ready", domain.Readiness);
        Assert.Contains("500", domain.ReadinessReason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The common case a two-state answer hides: mail is fine, but not
    /// perfect, so raising the policy is a decision about a known remainder
    /// rather than a formality.
    /// </summary>
    [Fact]
    public void AlmostPerfectIsConditionalRatherThanReady()
    {
        var domain = Domain(messages: 1000, passing: 970);

        Assert.Equal("Conditional", domain.Readiness);
        Assert.Contains("30 message(s) would be affected", domain.ReadinessReason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainAlreadyEnforcingHasNothingLeftToDecide()
    {
        Assert.Equal("Enforcing", Domain(policy: "reject").Readiness);
        Assert.Equal("Enforcing", Domain(policy: "quarantine").Readiness);
    }

    [Fact]
    public void ADomainNobodyReportedOnIsNotJudged()
    {
        var domain = Domain(messages: 0, passing: 0);

        Assert.Equal("No mail seen", domain.Readiness);
        Assert.Contains("nothing can be judged", domain.ReadinessReason, StringComparison.Ordinal);
    }

    // ---- the register the report ends on ------------------------------------

    /// <summary>
    /// Mail that is not arriving outranks everything, because it is the only
    /// finding with a cost the client can already feel.
    /// </summary>
    [Fact]
    public void LostMailIsTheFirstThingInTheRegister()
    {
        var report = new ClientReport
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains =
            [
                Domain("broken.example", "quarantine", messages: 100, passing: 40),
                Domain("fine.example", "none", messages: 100, passing: 100),
            ],
        };

        var first = report.Remediation[0];

        Assert.Equal("Critical", first.Priority);
        Assert.Contains("broken.example", first.Finding, StringComparison.Ordinal);
        Assert.Contains("refused", first.Impact, StringComparison.Ordinal);

        // And every item names who it is for and what finishing it looks
        // like, because a report ending in "consider p=reject" ends in
        // nothing.
        Assert.All(report.Remediation, item =>
        {
            Assert.NotEmpty(item.Owner);
            Assert.NotEmpty(item.Validation);
            Assert.NotEmpty(item.Action);
        });
    }

    /// <summary>
    /// Raising a policy is told LAST, after the mail is right. Told first, an
    /// MSP breaks a customer's invoicing and stops trusting the report.
    /// </summary>
    [Fact]
    public void RaisingThePolicyRanksBelowFixingTheMail()
    {
        var report = new ClientReport
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = [Domain("monitor.example", "none", messages: 100, passing: 100)],
            Sources =
            [
                new ReportSource
                {
                    SourceIp = "203.0.113.10", Messages = 200, Passing = 120, Failing = 80,
                },
            ],
        };

        var register = report.Remediation.ToList();
        var broken = register.FindIndex(i => i.Finding.Contains("203.0.113.10", StringComparison.Ordinal));
        var policy = register.FindIndex(i => i.Finding.Contains("p=none", StringComparison.Ordinal));

        Assert.True(broken >= 0 && policy >= 0, "both findings should be in the register");
        Assert.True(broken < policy, "the broken sender must come before raising the policy");
    }

    [Fact]
    public void AnEstateWithNothingWrongHasAnEmptyRegister()
    {
        var report = new ClientReport
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = [Domain("fine.example", "reject", messages: 100, passing: 100)],
        };

        Assert.Empty(report.Remediation);
    }
}
