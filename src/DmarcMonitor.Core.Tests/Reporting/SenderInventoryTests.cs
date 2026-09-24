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
            FailedBothNotAligned = 10,
            FailedBoth = 10,
        }) with { OverriddenMessages = 15 };

        var causes = report.FailureCauses.ToDictionary(c => c.Cause, c => c.Messages, StringComparer.Ordinal);

        Assert.Equal(200, causes["SPF passed, did not align"]);
        Assert.Equal(80, causes["DKIM verified, did not align"]);
        Assert.Equal(10, causes["Both checks passed, neither aligned"]);
        Assert.Equal(10, causes["Neither check passed"]);
        Assert.Equal(15, causes["Handled by the receiver"]);
    }

    /// <summary>
    /// The causes are a column somebody adds up, so they must not overlap.
    /// </summary>
    /// <remarks>
    /// They did. A message that passed both checks without aligning was
    /// counted under SPF and again under DKIM, so a real client report showed
    /// 9 + 6 + 94 where the truth was 4 + 1 + 5 + 94 - more failures than
    /// there was failing mail. Found by adding up the rendered report against
    /// the database rather than by reading the query.
    /// </remarks>
    [Fact]
    public void TheCausesSumToTheMailThatFailedAndNoMore()
    {
        var report = Report(new ReportSource
        {
            SourceIp = "203.0.113.9",
            Messages = 100,
            Passing = 0,
            Failing = 100,
            FailedSpfNotAligned = 4,
            FailedDkimNotAligned = 1,
            FailedBothNotAligned = 5,
            FailedBoth = 90,
        });

        var counted = report.FailureCauses
            .Where(c => c.Cause != "Handled by the receiver")
            .Sum(c => c.Messages);

        Assert.Equal(100, counted);
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
        var broken = register.FindIndex(i => i.Finding.Contains("not set up to prove", StringComparison.Ordinal));
        var policy = register.FindIndex(i => i.Finding.Contains("p=none", StringComparison.Ordinal));

        Assert.True(broken >= 0 && policy >= 0, "both findings should be in the register");
        Assert.True(broken < policy, "the broken sender must come before raising the policy");
    }

    /// <summary>
    /// One finding, not one row per host.
    /// </summary>
    /// <remarks>
    /// A security gateway is five hostnames and a bulk sender is a dozen. The
    /// register printed a row for each, so a real client report carried five
    /// High rows repeating one sentence about smtp003, smtp005 and
    /// cloud-sec-av, with the same action on every one. A reader gets through
    /// two of those and stops, which loses whatever was underneath.
    /// </remarks>
    [Fact]
    public void BrokenSendersAreOneFindingThatNamesThem()
    {
        var report = new ClientReport
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = [Domain("acme.example", "reject", messages: 1000, passing: 1000)],
            Sources =
            [
                Broken("smtp003.vendor.example", 20),
                Broken("smtp005.vendor.example", 12),
                Broken("smtp007.vendor.example", 3),
                Broken("smtp009.vendor.example", 2),
                Broken("smtp011.vendor.example", 1),
            ],
        };

        var item = Assert.Single(report.Remediation, i => i.Finding.Contains("not set up to prove", StringComparison.Ordinal));

        Assert.Contains("5 service(s)", item.Finding, StringComparison.Ordinal);
        Assert.Contains("38 message(s) affected", item.Finding, StringComparison.Ordinal);

        // Busiest first, and the tail counted rather than listed.
        Assert.Contains("smtp003.vendor.example", item.Finding, StringComparison.Ordinal);
        Assert.Contains("and 1 more", item.Finding, StringComparison.Ordinal);
        Assert.DoesNotContain("smtp011.vendor.example", item.Finding, StringComparison.Ordinal);
    }

    /// <summary>
    /// Volume decides urgency, not the class on its own.
    /// </summary>
    /// <remarks>
    /// A finding worth one message ranked High beside one worth twenty-three,
    /// because the category set the priority and the size set nothing. Four
    /// High rows worth a single message each teach a reader to skip the
    /// column.
    /// </remarks>
    [Fact]
    public void ASingleMessageIsNotUrgent()
    {
        var small = new ClientReport
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = [Domain("acme.example", "reject", messages: 1000, passing: 1000)],
            Sources = [Broken("smtp003.vendor.example", 1)],
        };

        Assert.Equal("Medium", Assert.Single(small.Remediation).Priority);

        var real = small with { Sources = [Broken("smtp003.vendor.example", 40)] };
        Assert.Equal("High", Assert.Single(real.Remediation).Priority);
    }

    private static ReportSource Broken(string name, long failing) =>
        new()
        {
            SourceIp = "203.0.113." + Math.Abs(name.GetHashCode() % 200 + 1),
            ReverseName = name,
            Messages = failing,
            Passing = 0,
            Failing = failing,
            AuthenticatedFor = "vendor.example",
        };

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

/// <summary>
/// The sentence an executive reads and repeats, and the columns under it.
///
/// "DMARC passed 98% of messages" is a fact nobody can act on. A state, the
/// number behind it, and what it means for a decision about enforcement is
/// one somebody can take to a meeting.
/// </summary>
public sealed class VerdictTests
{
    private static ReportDomainHealth Domain(
        string name = "acme.example", string policy = "reject",
        long messages = 1000, long passing = 1000, long spfAligned = 900, long dkimAligned = 950) =>
        new()
        {
            Domain = name,
            Policy = policy,
            Messages = messages,
            Passing = passing,
            SpfAligned = spfAligned,
            DkimAligned = dkimAligned,
        };

    private static ClientReport Report(
        IReadOnlyList<ReportDomainHealth>? domains = null, IReadOnlyList<ReportSource>? sources = null) =>
        new()
        {
            ClientName = "Acme",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = domains ?? [Domain()],
            Sources = sources ?? [],
            Messages = (domains ?? [Domain()]).Sum(d => d.Messages),
            Passing = (domains ?? [Domain()]).Sum(d => d.Passing),
        };

    /// <summary>
    /// A domain losing mail outranks a good average, because an average across
    /// an estate is how a broken domain stays invisible.
    /// </summary>
    [Fact]
    public void ADomainLosingMailIsTheVerdictWhateverTheAverageSays()
    {
        var report = Report(
        [
            Domain("fine.example", messages: 1000, passing: 1000),
            Domain("broken.example", "quarantine", messages: 100, passing: 40),
        ]);

        // Already at p=quarantine, so the next step is reject. "Not ready
        // for enforcement" was false of a domain that is enforcing, and a
        // client reading the verdict and then the record saw a contradiction.
        Assert.StartsWith("Not ready for p=reject.", report.Verdict, StringComparison.Ordinal);
        Assert.Contains("broken.example", report.Verdict, StringComparison.Ordinal);
        Assert.Contains("60", report.Verdict, StringComparison.Ordinal);
    }

    /// <summary>
    /// Most of this mail authenticated - as the vendor. "Failed to
    /// authenticate" is wrong about it, and "those are going to junk" claims a
    /// disposition the report does not establish per message.
    /// </summary>
    [Fact]
    public void TheVerdictSaysDmarcAndDoesNotClaimWhatReceiversDid()
    {
        var report = Report([Domain("broken.example", "quarantine", messages: 100, passing: 40)]);

        Assert.Contains("did not pass DMARC", report.Verdict, StringComparison.Ordinal);
        Assert.DoesNotContain("failed to authenticate", report.Verdict, StringComparison.Ordinal);
        Assert.DoesNotContain("going to junk", report.Verdict, StringComparison.Ordinal);
    }

    [Fact]
    public void MisconfiguredSendersBecomeADecisionOnlyTheClientCanMake()
    {
        var report = Report(
            [Domain("acme.example", "quarantine")],
            [new ReportSource
            {
                SourceIp = "203.0.113.9", ReverseName = "smtp.vendor.example",
                Messages = 50, Passing = 10, Failing = 40, AuthenticatedFor = "vendor.example",
            }]);

        var ask = Assert.IsType<string>(report.DecisionRequested);
        Assert.Contains("smtp.vendor.example", ask, StringComparison.Ordinal);
        Assert.Contains("custom DKIM", ask, StringComparison.Ordinal);
        Assert.Contains("Keep p=quarantine", ask, StringComparison.Ordinal);

        Assert.Null(Report([Domain()]).DecisionRequested);
    }

    [Fact]
    public void AnUnenforcedDomainLosingMailIsNotReadyForEnforcement()
    {
        var report = Report([Domain("broken.example", "none", messages: 100, passing: 40)]);

        Assert.StartsWith("Not ready for enforcement.", report.Verdict, StringComparison.Ordinal);
        Assert.DoesNotContain("arriving", report.Verdict, StringComparison.Ordinal);
    }

    /// <summary>
    /// A verdict from a fraction of the month says so where it is read.
    /// </summary>
    [Fact]
    public void AThinMonthCarriesItsCaveatInTheVerdict()
    {
        var days = Enumerable.Range(1, 30).Select(d => new DayPoint
        {
            Day = new DateOnly(2026, 9, d), Reported = d <= 14, Messages = d <= 14 ? 10 : 0, Passing = d <= 14 ? 10 : 0,
        }).ToList();

        var thin = Report() with { Daily = days };
        Assert.Contains("reports arrived for 14 of 30 days", thin.Verdict, StringComparison.Ordinal);

        var full = Report() with { Daily = [.. days.Select(d => d with { Reported = true })] };
        Assert.DoesNotContain("Confidence is limited", full.Verdict, StringComparison.Ordinal);
    }

    [Fact]
    public void AMonitoringDomainWithBrokenSendersIsConditional()
    {
        var report = Report(
            [Domain("watched.example", "none", messages: 1000, passing: 1000)],
            [new ReportSource { SourceIp = "203.0.113.9", Messages = 50, Passing = 10, Failing = 40 }]);

        Assert.StartsWith("Conditional readiness.", report.Verdict, StringComparison.Ordinal);
        Assert.Contains("before", report.Verdict, StringComparison.Ordinal);
    }

    [Fact]
    public void AMonitoringDomainWithNothingBrokenIsReady()
    {
        var report = Report([Domain("watched.example", "none", messages: 1000, passing: 1000)]);

        Assert.StartsWith("Ready for enforcement.", report.Verdict, StringComparison.Ordinal);
    }

    [Fact]
    public void NoMailIsSaidRatherThanScored()
    {
        var report = Report([Domain(messages: 0, passing: 0, spfAligned: 0, dkimAligned: 0)]);

        Assert.Contains("No mail was reported", report.Verdict, StringComparison.Ordinal);
    }

    /// <summary>
    /// Aligned is not the same as passed, and the report must not print one
    /// for the other.
    /// </summary>
    /// <remarks>
    /// A vendor passes SPF for its own envelope domain on every message it
    /// sends. Printed as the domain's SPF figure, a client is shown 100%
    /// beside mail nobody can prove is theirs. DMARC can be higher than either
    /// aligned figure, because it needs only one of them.
    /// </remarks>
    [Fact]
    public void AlignedRatesAreTheirOwnFigures()
    {
        var domain = Domain(messages: 1000, passing: 964, spfAligned: 896, dkimAligned: 891);

        Assert.Equal(96.4, domain.PassRate);
        Assert.Equal(89.6, domain.SpfAlignedRate);
        Assert.Equal(89.1, domain.DkimAlignedRate);
    }

    [Fact]
    public void TheRecordIsTheOneThatWasInForce()
    {
        var domain = new ReportDomainHealth
        {
            Domain = "acme.example", Policy = "quarantine", SubdomainPolicy = "none", Pct = 50,
            Messages = 10, Passing = 10,
        };

        Assert.Equal("v=DMARC1; p=quarantine; sp=none; pct=50", domain.Record);

        // And where no report reached us, it says so rather than inventing one.
        var unknown = new ReportDomainHealth { Domain = "quiet.example", PolicyKnown = false };
        Assert.Contains("not known", unknown.Record, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryRegisterItemCarriesATarget()
    {
        var report = Report([Domain("watched.example", "none", messages: 100, passing: 40)]);

        Assert.All(report.Remediation, item => Assert.NotEmpty(item.Target));
        Assert.Equal("7 days", Assert.Single(report.Remediation, i => i.Priority == "Critical").Target);
    }
}

/// <summary>
/// A month nobody reported on, which is not a clean month.
/// </summary>
/// <remarks>
/// Four of ten real clients had no data for September, and each of their
/// reports printed, under "What to do next": "Nothing. Every domain is
/// enforcing, its own mail is arriving, and no sender needs correcting."
/// The same page showed mortonnd.gov at p=none, no messages at all, and
/// "confirm whether this domain sends mail" - three claims contradicted by
/// the table above them. An empty register is not an all-clear.
/// </remarks>
public sealed class QuietMonthTests
{
    private static ClientReport Report(string policy = "none") =>
        new()
        {
            ClientName = "Morton ND",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Domains = [new ReportDomainHealth { Domain = "mortonnd.gov", Policy = policy }],
        };

    [Fact]
    public void AMonthWithNoReportsIsAFindingRatherThanAnAllClear()
    {
        var item = Assert.Single(Report().Remediation);

        Assert.Contains("No receiver reported", item.Finding, StringComparison.Ordinal);
        Assert.Contains("mortonnd.gov", item.Finding, StringComparison.Ordinal);

        // With something to actually do, and a way to know it is finished.
        Assert.Contains("rua", item.Action, StringComparison.Ordinal);
        Assert.NotEmpty(item.Target);
        Assert.NotEmpty(item.Validation);
    }

    /// <summary>
    /// Silence over an unenforcing domain is worse than silence over an
    /// enforcing one: nothing is watching and nothing is stopping anybody.
    /// </summary>
    [Fact]
    public void SilenceOverAnUnprotectedDomainRanksHigher()
    {
        Assert.Equal("High", Assert.Single(Report().Remediation).Priority);
        Assert.Equal("Medium", Assert.Single(Report("reject").Remediation).Priority);
    }

    [Fact]
    public void TheQuietMonthSaysSoWhereItSaysWhatWasCovered()
    {
        var report = Report() with
        {
            Daily = [.. Enumerable.Range(1, 30).Select(d => new DayPoint
            {
                Day = new DateOnly(2026, 9, d),
                Reported = false,
            })],
        };

        var days = Assert.Single(report.Covered, f => f.Label == "Days covered");

        Assert.Equal("0 of 30", days.Value);
        Assert.Contains("No receiver reported on any day", days.Note, StringComparison.Ordinal);
    }
}

/// <summary>
/// What the month's work was, for the client with nothing wrong.
/// </summary>
/// <remarks>
/// The healthy estate's report said "Protected" and "Nothing to do" over
/// half a page of white space - sent monthly to the client happiest with the
/// service, and reading as an invoice with no work attached.
/// </remarks>
public sealed class CoveredTests
{
    private static ClientReport Report(long stopped = 0, long overridden = 0) =>
        new()
        {
            ClientName = "ND United",
            ProviderName = "NRG Tech Services",
            Period = ReportPeriod.ForMonth(2026, 9),
            Messages = 318,
            Passing = 318,
            OverriddenMessages = overridden,
            Domains = [new ReportDomainHealth
            {
                Domain = "ndunited.org", Policy = "quarantine", Messages = 318, Passing = 318,
            }],
            Daily = [.. Enumerable.Range(1, 30).Select(d => new DayPoint
            {
                Day = new DateOnly(2026, 9, d),
                Reported = true,
                Messages = 10,
                Passing = 10,
                Rejected = stopped / 30,
            })],
        };

    [Fact]
    public void AHealthyMonthStillSaysWhatWasDone()
    {
        var covered = Report().Covered;

        Assert.Contains(covered, f => f.Label == "Days covered" && f.Value == "30 of 30");
        Assert.Contains(covered, f => f.Label == "Messages examined" && f.Value == "318");
        Assert.Contains(covered, f => f.Label == "Domains watched" && f.Value == "1");
        Assert.All(covered, f => Assert.NotEmpty(f.Note));
    }

    /// <summary>
    /// Protection as delivered, taken from what the receivers did rather than
    /// from the failure count.
    /// </summary>
    /// <remarks>
    /// A message that failed under p=none was delivered. Counted as stopped,
    /// it would tell a client they were protected by a policy that asked for
    /// nothing - which is the single most consequential thing a report of
    /// this kind can get wrong.
    /// </remarks>
    [Fact]
    public void WhatTheReceiversActuallyDidIsWhatIsClaimed()
    {
        Assert.DoesNotContain(Report().Covered, f => f.Label.StartsWith("Turned away", StringComparison.Ordinal));

        var busy = Report(stopped: 600);

        Assert.Equal(600, busy.Stopped);
        Assert.Contains(busy.Covered, f => f.Label.StartsWith("Turned away", StringComparison.Ordinal));
    }

    [Fact]
    public void ForwardedMailIsNamedAsForwardedRatherThanAsFailure()
    {
        var forwarded = Assert.Single(
            Report(overridden: 40).Covered,
            f => f.Label.StartsWith("Forwarded", StringComparison.Ordinal));

        Assert.Equal("40", forwarded.Value);
        Assert.Contains("Mailing lists", forwarded.Note, StringComparison.Ordinal);
    }
}
