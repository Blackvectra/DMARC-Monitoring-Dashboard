using DmarcMonitor.Core.Reporting;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Rendering the client report.
///
/// Two things are load-bearing here. The file must stand alone, because it is
/// opened as an email attachment on a phone with no network and printed to PDF
/// for an accountant. And everything drawn from the database must be escaped:
/// organisation names, domains and record values all arrive inside reports
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
    public void SummarisesALongTailRatherThanPrintingAllOfIt()
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

        Assert.Contains("and 5 more source(s)", html, StringComparison.Ordinal);
        Assert.Contains("500 message(s)", html, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsANullReport() =>
        Assert.Throws<ArgumentNullException>(() => ClientReportRenderer.ToHtml(null!));
}
