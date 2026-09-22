using System.Text;
using DmarcMonitor.Core.Reporting;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using Xunit;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// The PDF a client receives.
///
/// The HTML is what an operator reads on screen; this is what goes out by
/// email every month, and the two are different jobs. An .html attachment is
/// the single thing a mail gateway is most likely to strip or warn about, and
/// a customer warned about the document their security provider just sent them
/// has learned the wrong lesson.
///
/// Asserted against the document model rather than by parsing a PDF back: a
/// test that checks the bytes begin with %PDF proves the library works, not
/// that the client's own figures reached the page.
/// </summary>
public sealed class ClientReportPdfTests
{
    private static ClientReport Report(
        string client = "Acme", string provider = "NRG Tech Services",
        long messages = 1000, long passing = 964, string policy = "reject") =>
        new()
        {
            ClientName = client,
            ProviderName = provider,
            Period = ReportPeriod.ForMonth(2026, 9),
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            Domains =
            [
                new ReportDomainHealth
                {
                    Domain = "acme.example",
                    Policy = policy,
                    Messages = messages,
                    Passing = passing,
                    SpfAligned = 896,
                    DkimAligned = 891,
                },
            ],
            Sources =
            [
                new ReportSource { SourceIp = "203.0.113.1", Messages = 900, Passing = 900 },
                new ReportSource
                {
                    SourceIp = "203.0.113.9", ReverseName = "smtp.vendor.example",
                    Messages = 100, Passing = 64, Failing = 36,
                    AuthenticatedFor = "vendor.example", FailedSpfNotAligned = 36,
                },
            ],
        };

    private static string Text(Document document)
    {
        // Everything the reader will see, flattened. Enough to assert a figure
        // reached the page without asserting where on it.
        var text = new StringBuilder();

        void Walk(object? node)
        {
            switch (node)
            {
                case Text t: text.Append(t.Content).Append(' '); break;
                case FormattedText f: foreach (var e in f.Elements) { Walk(e as DocumentObject); } break;
                case Paragraph p: foreach (var e in p.Elements) { Walk(e as DocumentObject); } text.Append('\n'); break;
                case Cell c: foreach (var e in c.Elements) { Walk(e as DocumentObject); } break;
                case Row r: for (var i = 0; i < r.Cells.Count; i++) { Walk(r.Cells[i]); } break;
                case Table tb: for (var i = 0; i < tb.Rows.Count; i++) { Walk(tb.Rows[i]); } break;
                case Section s:
                    foreach (var e in s.Elements) { Walk(e as DocumentObject); }
                    foreach (var e in s.Footers.Primary.Elements) { Walk(e as DocumentObject); }
                    break;
                case Document d: for (var i = 0; i < d.Sections.Count; i++) { Walk(d.Sections[i]); } break;
            }
        }

        Walk(document);
        return text.ToString();
    }

    [Fact]
    public void TheClientAndThePeriodAreOnTheDocument()
    {
        var text = Text(ClientReportPdf.Build(Report()));

        Assert.Contains("Acme", text, StringComparison.Ordinal);
        Assert.Contains("September 2026", text, StringComparison.Ordinal);
        Assert.Contains("NRG Tech Services", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The sentence the whole document exists to deliver.
    /// </summary>
    [Fact]
    public void TheVerdictLeadsIt()
    {
        var report = Report();
        var text = Text(ClientReportPdf.Build(report));

        Assert.Contains(report.Verdict, text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Aligned rates, not raw ones. A vendor passes SPF for its own domain on
    /// every message; printed as the domain's figure it tells a client a
    /// broken domain is fine.
    /// </summary>
    [Fact]
    public void TheDomainTableCarriesAlignedRates()
    {
        var text = Text(ClientReportPdf.Build(Report()));

        Assert.Contains("SPF aligned", text, StringComparison.Ordinal);
        Assert.Contains("DKIM aligned", text, StringComparison.Ordinal);
        Assert.Contains("89.6%", text, StringComparison.Ordinal);
        Assert.Contains("89.1%", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TheActionsAndTheirDatesAreOnIt()
    {
        var report = Report();
        var text = Text(ClientReportPdf.Build(report));

        Assert.Contains("What to do next", text, StringComparison.Ordinal);

        var item = Assert.Single(report.Remediation);
        Assert.Contains(item.Priority, text, StringComparison.Ordinal);
        Assert.Contains(item.Target, text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The reason this renderer exists rather than a print dialog: the page
    /// furniture is ours. A browser stamps its own address and the date on
    /// every page of a document a customer is paying for.
    /// </summary>
    [Fact]
    public void TheFooterIsOursAndCarriesThePageNumbers()
    {
        var document = ClientReportPdf.Build(Report());
        var footer = document.Sections[0]!.Footers.Primary;

        var text = Text(document);
        Assert.Contains("prepared by NRG Tech Services", text, StringComparison.Ordinal);
        Assert.Contains("Page", text, StringComparison.Ordinal);

        // The page number sits on the right margin. Computed from the A4 width
        // because PageSetup.PageWidth is empty until render time, and a zero
        // tab stop put the number against the text.
        var paragraph = (Paragraph)footer.Elements[0]!;
        Assert.NotEmpty(paragraph.Format.TabStops);
        Assert.True(paragraph.Format.TabStops[0]!.Position.Centimeter > 15);
    }

    [Fact]
    public void ItSaysWhichDomainsItCovers()
    {
        // Asked for so nobody sends a report and then wonders what was in it.
        var text = Text(ClientReportPdf.Build(Report()));

        Assert.Contains("Domains covered: acme.example", text, StringComparison.Ordinal);
    }

    [Fact]
    public void AMonthWithNoMailIsStillADocument()
    {
        // Silence from a monitoring provider is indistinguishable from a
        // provider that stopped, so the empty month is still sent.
        var quiet = Report(messages: 0, passing: 0);

        var text = Text(ClientReportPdf.Build(quiet));
        Assert.Contains("No mail was reported", text, StringComparison.Ordinal);

        var bytes = ClientReportPdf.Render(quiet);
        Assert.True(bytes.Length > 1000);
    }

    /// <summary>
    /// It renders, on a machine with no fonts installed, which is the ordinary
    /// case for the container that will produce these every month.
    /// </summary>
    [Fact]
    public void ItRendersToARealPdf()
    {
        var bytes = ClientReportPdf.Render(Report());

        Assert.True(bytes.Length > 5000, $"a report of {bytes.Length} bytes is not a rendered document");
        Assert.Equal("%PDF", Encoding.ASCII.GetString(bytes, 0, 4));
    }

    [Fact]
    public void RenderingTwiceDoesNotFightOverTheFontResolver()
    {
        // PDFsharp keeps the resolver in a static and throws if it is assigned
        // again after anything has been drawn. A scheduled run and a web
        // request arriving together is the ordinary case.
        var first = ClientReportPdf.Render(Report());
        var second = ClientReportPdf.Render(Report(client: "Other"));

        Assert.True(first.Length > 5000);
        Assert.True(second.Length > 5000);
    }

    [Fact]
    public void TheFontLicenceTravelsWithTheFont()
    {
        // SIL OFL 1.1 requires it, and a licence nobody can find is not one.
        Assert.Contains("SIL OPEN FONT LICENSE", ReportFonts.License, StringComparison.Ordinal);
    }

    /// <summary>
    /// The MSP's mark, not this product's.
    /// </summary>
    /// <remarks>
    /// The report is the part of the platform a customer ever sees, so
    /// white-labelling that stops at the screen is not white-labelling. The
    /// HTML carried the colour, the logo and the contact block from the start;
    /// the PDF carried only the provider's name.
    /// </remarks>
    [Fact]
    public void TheOrganizationsBrandingReachesThePdf()
    {
        var branded = Report() with
        {
            BrandColor = "#0f766e",
            ContactBlock = "dmarc@nrgtechservices.com\n(701) 555-0134",
        };

        var document = ClientReportPdf.Build(branded);

        // The rule under the client's name is the organization's colour.
        var section = document.Sections[0]!;
        var rule = Find(section, p => p.Format.Borders.Bottom.Width.Point > 0 && !p.Format.Borders.Bottom.Color.IsEmpty);
        Assert.Equal(new Color(0x0F, 0x76, 0x6E), rule.Format.Borders.Bottom.Color);

        // The contact block is in the footer, on one line: a newline inside a
        // MigraDoc paragraph is a control character, not a break.
        var text = Text(document);
        Assert.Contains("dmarc@nrgtechservices.com · (701) 555-0134", text, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnbrandedReportStillRenders()
    {
        var text = Text(ClientReportPdf.Build(Report()));

        Assert.DoesNotContain("·  ·", text, StringComparison.Ordinal);
        Assert.True(ClientReportPdf.Render(Report()).Length > 5000);
    }

    /// <summary>
    /// A logo this renderer cannot draw does not cost the client their month.
    /// </summary>
    /// <remarks>
    /// The store accepts GIF, WebP and SVG because a browser draws them in
    /// the sidebar. PDFsharp does not, and an exception where the report
    /// should be is a worse answer than a report with the name on it.
    /// </remarks>
    [Theory]
    [InlineData("data:image/svg+xml;base64,PHN2Zy8+")]
    [InlineData("data:image/gif;base64,R0lGODlhAQABAAAAACw=")]
    [InlineData("not a data url at all")]
    public void ALogoThatCannotBeDrawnIsSkippedRatherThanThrown(string logo)
    {
        var bytes = ClientReportPdf.Render(Report() with { BrandLogo = logo });

        Assert.True(bytes.Length > 5000);
    }

    [Fact]
    public void APngLogoIsDrawn()
    {
        // An 8x8 PNG, which is enough to prove the decode path: the logo an
        // organization uploads is a data: URL, and PDFsharp takes base64
        // rather than a URL.
        const string Png =
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEUlEQVR4nGPg"
            + "L8vDihiGlgQApWE8wfekj3cAAAAASUVORK5CYII=";

        var document = ClientReportPdf.Build(Report() with { BrandLogo = Png });
        var section = document.Sections[0]!;

        var images = 0;
        foreach (var element in section.Elements)
        {
            if (element is MigraDoc.DocumentObjectModel.Shapes.Image) { images++; }
        }

        Assert.Equal(1, images);
        Assert.True(ClientReportPdf.Render(Report() with { BrandLogo = Png }).Length > 5000);
    }

    private static Paragraph Find(Section section, Func<Paragraph, bool> predicate)
    {
        foreach (var element in section.Elements)
        {
            if (element is Paragraph p && predicate(p)) { return p; }
        }

        throw new InvalidOperationException("no paragraph matched");
    }

    [Fact]
    public void ANullReportIsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => ClientReportPdf.Build(null!));
        Assert.Throws<ArgumentNullException>(() => ClientReportPdf.Render(null!));
    }
}
