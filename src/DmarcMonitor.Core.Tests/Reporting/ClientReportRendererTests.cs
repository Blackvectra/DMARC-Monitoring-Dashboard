using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Rendering the client report.
///
/// Two things are load-bearing here. The file must stand alone, because it is
/// opened as an email attachment on a phone with no network and printed to PDF
/// for an accountant. And everything drawn from the database must be escaped:
/// organization names, domains and record values all arrive inside reports
/// sent by third parties, so they are attacker-influenceable text being pasted
/// into a document the client forwards to their own staff.
/// </summary>
public sealed class ClientReportRendererTests
{
    private static ReportPeriod August => ReportPeriod.ForMonth(2026, 8);

    private static ClientReport Report(
        string clientName = "Acme Corp",
        IReadOnlyList<ReportDomainHealth>? domains = null,
        IReadOnlyList<ReportSource>? sources = null,
        IReadOnlyList<ReportChange>? changes = null,
        long messages = 1000,
        long passing = 950) => new()
        {
            ClientName = clientName,
            ProviderName = "NRG Tech Services",
            Period = August,
            Domains = domains ?? [new ReportDomainHealth { Domain = "acme.com", Policy = "reject", Messages = messages, Passing = passing }],
            Sources = sources ?? [],
            Changes = changes ?? [],
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
        };

    // ---- escaping ------------------------------------------------------------

    [Fact]
    public void EscapesTextThatCameOutOfAReport()
    {
        // A source IP field is not free text in a well-formed report, but the
        // report was written by somebody else's mail server and this document
        // gets forwarded inside the client's business.
        var html = ClientReportRenderer.ToHtml(Report(
            sources:
            [
                new ReportSource
                {
                    SourceIp = "<script>alert(1)</script>",
                    Messages = 10,
                    Failing = 10,
                    Domains = ["acme.com"],
                },
            ],
            messages: 1000, passing: 990));

        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void EscapesTheClientName()
    {
        var html = ClientReportRenderer.ToHtml(Report(clientName: "Bob & Sons <Ltd>"));

        Assert.DoesNotContain("<Ltd>", html, StringComparison.Ordinal);
        Assert.Contains("Bob &amp; Sons", html, StringComparison.Ordinal);
    }

    [Fact]
    public void EscapesDnsRecordValuesInTheChangeLog()
    {
        // The most likely place for a raw angle bracket: a TXT value, or a
        // reason string somebody typed.
        var html = ClientReportRenderer.ToHtml(Report(changes:
        [
            new ReportChange
            {
                RecordName = "_dmarc.acme.com",
                RecordType = "TXT",
                Reason = "Move to p=reject <after baseline>",
                AppliedAt = new DateTimeOffset(2026, 8, 12, 0, 0, 0, TimeSpan.Zero),
            },
        ]));

        Assert.DoesNotContain("<after baseline>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;after baseline&gt;", html, StringComparison.Ordinal);
    }

    // ---- standing alone ------------------------------------------------------

    [Fact]
    public void FetchesNothingFromTheNetwork()
    {
        // Opened offline, from an attachment. One external stylesheet or font
        // and the report looks broken exactly when it is being judged.
        var html = ClientReportRenderer.ToHtml(Report(
            sources: [new ReportSource { SourceIp = "203.0.113.9", Messages = 10, Failing = 10, Domains = ["acme.com"] }],
            changes: [new ReportChange { RecordName = "_dmarc.acme.com", RecordType = "TXT" }]));

        Assert.DoesNotContain("http://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.Ordinal);
    }

    [Fact]
    public void IsAWholeDocument()
    {
        var html = ClientReportRenderer.ToHtml(Report());

        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.EndsWith("</html>\n", html, StringComparison.Ordinal);
        Assert.Contains("<style>", html, StringComparison.Ordinal);
        Assert.Contains("@media print", html, StringComparison.Ordinal);
    }

    // ---- what it says --------------------------------------------------------

    [Fact]
    public void LeadsWithTheSummaryBeforeAnyTable()
    {
        // The whole point of the layout: the answer, then the evidence.
        var html = ClientReportRenderer.ToHtml(Report());

        Assert.True(html.IndexOf("In short", StringComparison.Ordinal)
                  < html.IndexOf("<table", StringComparison.Ordinal));
    }

    [Fact]
    public void SaysNobodyRatherThanLeavingTheSectionOut()
    {
        // An absent section reads as "not checked". A client needs to see that
        // it was checked and was clean.
        var html = ClientReportRenderer.ToHtml(Report(messages: 1000, passing: 1000));

        Assert.Contains("Who tried to send mail as you", html, StringComparison.Ordinal);
        Assert.Contains("Nobody.", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysNoChangesWereNeededRatherThanLeavingTheSectionOut()
    {
        var html = ClientReportRenderer.ToHtml(Report());

        Assert.Contains("What we did this month", html, StringComparison.Ordinal);
        Assert.Contains("No changes were needed", html, StringComparison.Ordinal);
    }

    [Fact]
    public void KeepsARolledBackChangeAndLabelsIt()
    {
        // Hiding it would make the report a sales document. A client should
        // hear about a reverted change from their provider, not find it later.
        var html = ClientReportRenderer.ToHtml(Report(changes:
        [
            new ReportChange
            {
                RecordName = "_dmarc.acme.com",
                RecordType = "TXT",
                Reason = "Move to p=quarantine",
                AppliedAt = new DateTimeOffset(2026, 8, 12, 0, 0, 0, TimeSpan.Zero),
                WasRolledBack = true,
            },
        ]));

        Assert.Contains("Reverted", html, StringComparison.Ordinal);
        Assert.Contains("Move to p=quarantine", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainThatSentNothingDoesNotReadAsTotalFailure()
    {
        // 0% next to 0 messages looks like everything failed.
        var html = ClientReportRenderer.ToHtml(Report(
            domains: [new ReportDomainHealth { Domain = "quiet.com", Policy = "reject", Messages = 0, Passing = 0 }],
            messages: 0, passing: 0));

        Assert.Contains("no mail", html, StringComparison.Ordinal);
        Assert.DoesNotContain(">0%<", html, StringComparison.Ordinal);
    }

    [Fact]
    public void NamesTheDomainsAndTheMonth()
    {
        var html = ClientReportRenderer.ToHtml(Report());

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("August 2026", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SummarizesALongTailRatherThanPrintingAllOfIt()
    {
        // Twenty rows of legitimate senders is a list nobody reads, but the
        // totals still have to add up, so the rest is counted rather than cut.
        var sources = Enumerable.Range(1, 20).Select(i => new ReportSource
        {
            SourceIp = $"203.0.113.{i}",
            Messages = 100,
            Passing = 100,
            Failing = 0,
            Domains = ["acme.com"],
        }).ToList();

        var html = ClientReportRenderer.ToHtml(Report(sources: sources, messages: 2000, passing: 2000));

        // Twenty addresses none of which belong to a service anybody knows, so
        // twenty rows: nothing is merged on a guess.
        Assert.Contains("and 5 more senders", html, StringComparison.Ordinal);
        Assert.Contains("500 messages", html, StringComparison.Ordinal);
    }

    [Fact]
    public void GathersOneServicesAddressesIntoOneRow()
    {
        // The reason this exists. A real client's August had 630 clean
        // sources, 618 of them Microsoft's load balancers; the table printed
        // fifteen of those and hid the twelve rows that were worth reading
        // behind "and 606 more". Gathered, Microsoft is one line and the
        // twelve are all visible.
        var microsoft = Enumerable.Range(1, 40).Select(i => new ReportSource
        {
            SourceIp = $"40.107.220.{i}",
            Messages = 10,
            Passing = 10,
            Failing = 0,
            Domains = ["acme.com"],
        });

        var theOneThatMatters = new ReportSource
        {
            SourceIp = "203.0.113.9",
            Messages = 5,
            Passing = 5,
            Failing = 0,
            Domains = ["acme.com"],
        };

        var html = ClientReportRenderer.ToHtml(
            Report(sources: [.. microsoft, theOneThatMatters], messages: 405, passing: 405));

        Assert.Contains("Microsoft 365", html, StringComparison.Ordinal);
        Assert.Contains("40 addresses", html, StringComparison.Ordinal);

        // Forty-one sources, two rows: no long tail to hide anything behind.
        Assert.DoesNotContain("more sender", html, StringComparison.Ordinal);
        Assert.Contains("203.0.113.9", html, StringComparison.Ordinal);

        // And the individual Microsoft addresses are gone from the document.
        Assert.DoesNotContain("40.107.220.1<", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysWhenTransportSecurityIsAnnouncedButNotEnforced()
    {
        // Parsed and stored from the first TLS report read, and never shown to
        // anybody until real data made it obvious: two live domains publish
        // MTA-STS in testing mode, where a receiver reports a mismatched
        // connection and delivers the mail anyway. The domain looks protected
        // in transit and is not.
        var html = ClientReportRenderer.ToHtml(Report(domains:
        [
            new ReportDomainHealth
            {
                Domain = "acme.com", Policy = "reject",
                Messages = 100, Passing = 100, MtaStsMode = "Testing",
            },
        ]));

        Assert.Contains("Transport security is not yet switched on", html, StringComparison.Ordinal);
        Assert.Contains("testing", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysNothingAboutTransportSecurityWhenItIsEnforcing()
    {
        // A report that comments on everything is a report nobody finishes.
        var html = ClientReportRenderer.ToHtml(Report(domains:
        [
            new ReportDomainHealth
            {
                Domain = "acme.com", Policy = "reject",
                Messages = 100, Passing = 100, MtaStsMode = "Enforce",
            },
        ]));

        Assert.DoesNotContain("Transport security", html, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsANullReport() =>
        Assert.Throws<ArgumentNullException>(() => ClientReportRenderer.ToHtml(null!));

    // ---- the chart -----------------------------------------------------------

    /// <summary>A month of days, with mail only on the ones listed.</summary>
    private static List<DayPoint> Days(params (int Day, long Messages, long Passing)[] mail)
    {
        var points = new List<DayPoint>();
        for (var d = 1; d <= 31; d++)
        {
            var row = mail.FirstOrDefault(m => m.Day == d);
            points.Add(row.Day == d
                ? new DayPoint { Day = new DateOnly(2026, 8, d), Reported = true, Messages = row.Messages, Passing = row.Passing }
                : new DayPoint { Day = new DateOnly(2026, 8, d), Reported = false });
        }
        return points;
    }

    [Fact]
    public void AMonthWithOneReportedDayStillDrawsSomething()
    {
        // Found on the real data. mcleanelectric.com was heard from on exactly
        // one day in August, so the line was a single move with nothing to
        // join to and the area had no width: the client's report carried an
        // empty rectangle where the chart should be, which reads as broken
        // software rather than as a quiet month.
        var html = ClientReportRenderer.ToHtml(Report() with { Daily = Days((28, 7, 4)) });

        Assert.Contains("class=\"t-dot\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AMonthOfRealTrafficDrawsTheLineRatherThanDots()
    {
        var html = ClientReportRenderer.ToHtml(
            Report() with { Daily = Days((1, 100, 90), (2, 120, 110), (3, 80, 80)) });

        Assert.Contains("class=\"t-line\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"t-dot\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AMonthWithNoMailAtAllDrawsNoChart()
    {
        // The summary above already says so in words, and an empty chart under
        // it reads as a rendering fault.
        var html = ClientReportRenderer.ToHtml(Report(messages: 0, passing: 0) with { Daily = Days() });

        Assert.DoesNotContain("class=\"trend\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void TheChartSaysWhenDaysAreMissingRatherThanDrawingThemFlat()
    {
        // A client who sees a dip needs to know whether their mail stopped or
        // the reporting did. Those are very different conversations.
        var html = ClientReportRenderer.ToHtml(
            Report() with { Daily = Days((1, 100, 90), (2, 120, 110)) });

        Assert.Contains("have no reports at all", html, StringComparison.Ordinal);
    }

    [Fact]
    public void TheChartNeverEmitsANumberTheBrowserCannotParse()
    {
        // NaN or Infinity in a path attribute renders as an empty chart with
        // nothing logged anywhere, which is the hardest kind of wrong to spot.
        var html = ClientReportRenderer.ToHtml(
            Report(messages: 0, passing: 0) with { Daily = Days((5, 0, 0), (6, 0, 0)) });

        Assert.DoesNotContain("NaN", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Infinity", html, StringComparison.Ordinal);
    }

    [Fact]
    public void TheChartCarriesNoScriptAndNoExternalReference()
    {
        // The whole document is opened from an email attachment, sometimes
        // with no network. Anything fetched from elsewhere is a broken image
        // at exactly the moment the report is being judged.
        var html = ClientReportRenderer.ToHtml(
            Report() with { Daily = Days((1, 100, 90), (2, 120, 110)) });

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", html, StringComparison.OrdinalIgnoreCase);
    }
}
