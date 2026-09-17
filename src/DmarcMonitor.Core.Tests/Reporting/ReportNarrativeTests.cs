using System.Globalization;
using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// The paragraph a client reads.
///
/// This is the only part of the product a paying customer sees every month, so
/// a sentence that is technically true but reads as reassuring when it should
/// not is the worst bug available here. Getting a number wrong is recoverable;
/// telling somebody they are protected when they are not is not.
/// </summary>
public sealed class ReportNarrativeTests
{
    private static ReportPeriod August => ReportPeriod.ForMonth(2026, 8);

    private static ReportDomainHealth Domain(
        string name = "acme.com", string policy = "reject", long messages = 1000, long passing = 1000) => new()
        {
            Domain = name,
            Policy = policy,
            Messages = messages,
            Passing = passing,
        };

    private static ReportSource Source(
        string ip = "203.0.113.9",
        long messages = 50,
        long passing = 0,
        string authenticatedFor = "",
        int otherClients = 0) => new()
        {
            SourceIp = ip,
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            AuthenticatedFor = authenticatedFor,
            Domains = ["acme.com"],
            OtherClientsAffected = otherClients,
        };

    private static ClientReport Report(
        IReadOnlyList<ReportDomainHealth>? domains = null,
        IReadOnlyList<ReportSource>? sources = null,
        IReadOnlyList<ReportChange>? changes = null,
        long messages = 1000,
        long passing = 1000,
        long previousMessages = 0,
        long previousPassing = 0) => new()
        {
            ClientName = "Acme Corp",
            ProviderName = "NRG Tech Services",
            Period = August,
            Domains = domains ?? [Domain()],
            Sources = sources ?? [],
            Changes = changes ?? [],
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            PreviousMessages = previousMessages,
            PreviousPassing = previousPassing,
        };

    private static string AllText(ReportSummary s) => s.Headline + " " + string.Join(" ", s.Points);

    // ---- the sentence that must never be wrong ------------------------------

    [Fact]
    public void ADomainAtPNoneIsNeverDescribedAsProtected()
    {
        // A perfect pass rate at p=none still means anybody can send as this
        // client and it will be delivered. Calling that protected is the one
        // thing this report must not do.
        var summary = ReportNarrative.Summarise(
            Report(domains: [Domain(policy: "none")], messages: 1000, passing: 1000));

        Assert.Contains("not yet protected", summary.Headline, StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);
    }

    [Fact]
    public void PartialEnforcementSaysHowManyRatherThanRoundingUp()
    {
        var summary = ReportNarrative.Summarise(Report(domains:
        [
            Domain("a.com", "reject"),
            Domain("b.com", "quarantine"),
            Domain("c.com", "none"),
        ]));

        Assert.Contains("2 of your 3 domains are protected", summary.Headline, StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);
    }

    [Fact]
    public void AFullyProtectedCleanMonthSaysThereIsNothingToDo()
    {
        var summary = ReportNarrative.Summarise(Report());

        Assert.Contains("protected", summary.Headline, StringComparison.Ordinal);
        Assert.False(summary.NeedsAttention);
    }

    [Fact]
    public void ProtectedButLosingOwnMailIsNotAQuietMonth()
    {
        var summary = ReportNarrative.Summarise(Report(messages: 1000, passing: 800));

        Assert.Contains("failing", summary.Headline, StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);
    }

    // ---- silence ------------------------------------------------------------

    [Fact]
    public void AMonthWithNoReportsSaysSoRatherThanReadingAsQuiet()
    {
        // Zeroes everywhere look like a calm month. They almost always mean
        // the record was changed or monitoring broke.
        var summary = ReportNarrative.Summarise(Report(messages: 0, passing: 0));

        Assert.Contains("No DMARC reports arrived", summary.Headline, StringComparison.Ordinal);
        Assert.Contains("changed or removed", AllText(summary), StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);
    }

    [Fact]
    public void ANoDataMonthDoesNotClaimAnythingWasBlocked()
    {
        var summary = ReportNarrative.Summarise(Report(messages: 0, passing: 0));

        Assert.DoesNotContain("refused", AllText(summary), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("%", AllText(summary), StringComparison.Ordinal);
    }

    // ---- impersonation ------------------------------------------------------

    [Fact]
    public void SaysWhatEnforcementActuallyDidWhenSomeoneSentAsTheClient()
    {
        var summary = ReportNarrative.Summarise(Report(
            domains: [Domain(policy: "reject", messages: 1000, passing: 940)],
            sources: [Source(messages: 60)],
            messages: 1000, passing: 940));

        var text = AllText(summary);
        Assert.Contains("could not prove otherwise", text, StringComparison.Ordinal);
        Assert.Contains("refused or sent to junk", text, StringComparison.Ordinal);
    }

    [Fact]
    public void DoesNotClaimAnythingWasStoppedWhenNothingIsEnforcing()
    {
        // The same impersonation at p=none was delivered. Saying it was
        // blocked would be the report's most damaging possible lie.
        var summary = ReportNarrative.Summarise(Report(
            domains: [Domain(policy: "none", messages: 1000, passing: 940)],
            sources: [Source(messages: 60)],
            messages: 1000, passing: 940));

        var text = AllText(summary);
        Assert.Contains("not yet enforcing", text, StringComparison.Ordinal);
        Assert.DoesNotContain("were refused", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TellsAClientWhenTheSameSourceIsHittingOthersToo()
    {
        // The difference between "somebody is after you" and "this is a
        // spray", which is the question a client asks first.
        var summary = ReportNarrative.Summarise(Report(
            sources: [Source(messages: 60, otherClients: 3)],
            messages: 1000, passing: 940));

        Assert.Contains("broad activity rather than", AllText(summary), StringComparison.Ordinal);
    }

    [Fact]
    public void AMisconfiguredServiceIsDescribedAsTheClientsOwnMail()
    {
        // Not an attack. A client who reads this as an attack panics about the
        // wrong thing and ignores the mail they are actually losing.
        var summary = ReportNarrative.Summarise(Report(
            sources: [Source(ip: "198.51.100.7", messages: 40, authenticatedFor: "mailchimpapp.net")],
            messages: 1000, passing: 960));

        var text = AllText(summary);
        Assert.Contains("service(s) you use", text, StringComparison.Ordinal);
        Assert.Contains("your own message(s) at risk", text, StringComparison.Ordinal);
        Assert.True(summary.NeedsAttention);

        // And the headline must not contradict it. A month with mail at risk
        // is not a month where nothing needed attention.
        Assert.DoesNotContain("nothing needed attention", summary.Headline, StringComparison.Ordinal);
    }

    // ---- comparison ---------------------------------------------------------

    [Fact]
    public void OmitsTheComparisonWhenThereIsNoPreviousMonth()
    {
        var summary = ReportNarrative.Summarise(Report(previousMessages: 0));

        Assert.DoesNotContain("July 2026", AllText(summary), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1000, 900, "up from")]
    [InlineData(1000, 1000, "unchanged")]
    public void ComparesAgainstThePreviousMonthWhenThereIsOne(
        long previousMessages, long previousPassing, string expected)
    {
        var summary = ReportNarrative.Summarise(Report(
            messages: 1000, passing: 1000,
            previousMessages: previousMessages, previousPassing: previousPassing));

        Assert.Contains(expected, AllText(summary), StringComparison.Ordinal);
    }

    [Fact]
    public void NamesThePreviousMonthWhenItReportsAChange()
    {
        var summary = ReportNarrative.Summarise(Report(
            messages: 1000, passing: 1000, previousMessages: 1000, previousPassing: 900));

        Assert.Contains("July 2026", AllText(summary), StringComparison.Ordinal);
    }

    // ---- guards -------------------------------------------------------------

    [Fact]
    public void EverySentenceIsWholeAndPunctuated()
    {
        // Half a sentence in a client-facing document reads as a bug in the
        // product, whatever the numbers say.
        var summary = ReportNarrative.Summarise(Report(
            domains: [Domain(policy: "none")],
            sources: [Source(messages: 60), Source(ip: "198.51.100.7", authenticatedFor: "x.net")],
            changes: [new ReportChange { RecordName = "_dmarc.acme.com", RecordType = "TXT" }],
            messages: 1000, passing: 900, previousMessages: 900, previousPassing: 880));

        Assert.EndsWith(".", summary.Headline, StringComparison.Ordinal);
        Assert.NotEmpty(summary.Points);
        foreach (var point in summary.Points)
        {
            Assert.EndsWith(".", point, StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(point));
        }
    }

    [Fact]
    public void NamesTheProviderRatherThanSayingWe()
    {
        // The report is forwarded. "We" in a document with no letterhead is
        // ambiguous the moment it leaves the client's inbox.
        var summary = ReportNarrative.Summarise(Report(
            sources: [Source(ip: "198.51.100.7", authenticatedFor: "x.net")],
            messages: 1000, passing: 960));

        Assert.Contains("NRG Tech Services", AllText(summary), StringComparison.Ordinal);
    }

    [Fact]
    public void NeverClaimsASubsetIsLargerThanTheSetItCameFrom()
    {
        // Found on real data: the impersonation sentence named 137 messages
        // and then said "210 of those" were stopped, because the second figure
        // counted every failing message on every enforcing domain - the
        // client's own misconfigured mail included. A client who spots one of
        // those stops believing the rest of the report.
        var report = Report(
            domains: [Domain(policy: "quarantine", messages: 4393, passing: 4183)],
            sources:
            [
                Source(ip: "203.0.113.9", messages: 137),                                  // impersonating
                Source(ip: "198.51.100.7", messages: 73, authenticatedFor: "vendor.net"),  // the client's own
            ],
            messages: 4393, passing: 4183);

        var summary = ReportNarrative.Summarise(report);
        var impersonation = Assert.Single(summary.Points, p => p.Contains("could not prove otherwise", StringComparison.Ordinal));

        // Every number in that sentence must be one the sentence is entitled
        // to use: the impersonating total and its source count, nothing wider.
        var numbers = System.Text.RegularExpressions.Regex
            .Matches(impersonation, @"\d[\d,]*")
            .Select(m => long.Parse(m.Value.Replace(",", ""), CultureInfo.InvariantCulture))
            .ToList();

        Assert.All(numbers, n => Assert.True(n <= 137, $"{n} is larger than the 137 message(s) the sentence is about"));
    }

    [Fact]
    public void TheHeadlineNeverContradictsNeedsAttention()
    {
        // The general form of the bug above: a reassuring headline sitting on
        // top of a month that needs something done. Once a client notices one
        // of those, nothing else in the report is believed either.
        ClientReport[] reports =
        [
            Report(domains: [Domain(policy: "none")]),
            Report(messages: 1000, passing: 700),
            Report(sources: [Source(ip: "198.51.100.7", authenticatedFor: "x.net")], messages: 1000, passing: 960),
            Report(messages: 0, passing: 0),
            Report(domains: [Domain("a.com", "reject"), Domain("b.com", "none")]),
        ];

        foreach (var report in reports)
        {
            var summary = ReportNarrative.Summarise(report);
            if (summary.NeedsAttention)
            {
                Assert.DoesNotContain("nothing needed attention", summary.Headline, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void RejectsANullReport() =>
        Assert.Throws<ArgumentNullException>(() => ReportNarrative.Summarise(null!));

    [Fact]
    public void NeverDividesByZeroForAClientWithNoDomains()
    {
        var summary = ReportNarrative.Summarise(Report(domains: [], messages: 0, passing: 0));

        Assert.False(string.IsNullOrWhiteSpace(summary.Headline));
    }
}
