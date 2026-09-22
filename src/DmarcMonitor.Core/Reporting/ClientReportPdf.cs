using System.Globalization;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// The client report as a PDF.
///
/// The HTML version is the one an operator reads on screen. This is the one a
/// client receives, every month, as an attachment - and that is a different
/// job. An .html attachment is the single thing a mail gateway is most likely
/// to strip, quarantine or warn about, and a customer who is warned about the
/// document their security provider just sent them has learned the wrong
/// lesson.
///
/// Drawn rather than printed, so this product owns the page furniture. A
/// browser's print dialog stamps the date, the tab title and
/// "localhost:5000" across the foot of every page; no stylesheet can stop it,
/// and it appears on a document somebody is paying for.
///
/// Both renderers read the same <see cref="ClientReport"/>, so the figures
/// cannot disagree. Where this one is shorter it is deliberately so: it
/// carries the verdict, the numbers, the domains, what is sending and what to
/// do, and leaves the long evidence tables to the HTML.
/// </summary>
public static class ClientReportPdf
{
    private static readonly Color Ink = new(0x18, 0x18, 0x1B);
    private static readonly Color Muted = new(0x71, 0x71, 0x7A);
    private static readonly Color Rule = new(0xE4, 0xE4, 0xE7);
    private static readonly Color Good = new(0x15, 0x80, 0x3D);
    private static readonly Color Bad = new(0xB9, 0x1C, 0x1C);
    private static readonly Color Warn = new(0xA1, 0x62, 0x07);

    /// <summary>Renders the report to PDF bytes.</summary>
    public static byte[] Render(ClientReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        ReportFonts.Install();

        var renderer = new PdfDocumentRenderer { Document = Build(report) };
        renderer.RenderDocument();

        using var stream = new MemoryStream();
        renderer.PdfDocument.Save(stream, closeStream: false);
        return stream.ToArray();
    }

    /// <summary>
    /// The document, before it is rendered.
    /// </summary>
    /// <remarks>
    /// Separate so the content can be asserted without parsing a PDF back
    /// again. A test that only checks the bytes start with %PDF proves the
    /// library works, not that the client's figures reached the page.
    /// </remarks>
    public static Document Build(ClientReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var document = new Document();
        document.Info.Title = $"{report.ClientName} - email authentication report, {report.Period.Label}";
        document.Info.Author = report.ProviderName;
        document.Info.Subject = "Monthly DMARC and email authentication summary";

        var normal = document.Styles["Normal"]!;
        normal.Font.Name = ReportFonts.Family;
        normal.Font.Size = 9.5;
        normal.Font.Color = Ink;
        normal.ParagraphFormat.SpaceAfter = 6;
        normal.ParagraphFormat.LineSpacingRule = LineSpacingRule.Multiple;
        normal.ParagraphFormat.LineSpacing = 1.25;

        var section = document.AddSection();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(1.8);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(1.8);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(1.9);
        section.PageSetup.RightMargin = Unit.FromCentimeter(1.9);

        Footer(section, report);

        Header(section, report);
        Verdict(section, report);
        Figures(section, report);
        Domains(section, report);
        Senders(section, report);
        WhyFailed(section, report);
        Actions(section, report);
        Covered(section, report);
        Explainer(section, report);

        return document;
    }

    // ---- the page furniture this product owns -------------------------------

    private static void Footer(Section section, ClientReport report)
    {
        // The reason this renderer exists. A browser puts its own address and
        // the date here; a client's document says who prepared it, what period
        // it covers, and which page they are on.
        var footer = section.Footers.Primary.AddParagraph();
        footer.Format.Font.Size = 7.5;
        footer.Format.Font.Color = Muted;
        footer.Format.Borders.Top.Width = 0.5;
        footer.Format.Borders.Top.Color = Rule;
        footer.Format.SpaceBefore = 6;
        footer.AddText($"{report.ClientName} · {report.Period.Label} · prepared by {report.ProviderName}");

        footer.AddTab();
        footer.AddText("Page ");
        footer.AddPageField();
        footer.AddText(" of ");
        footer.AddNumPagesField();

        // From the A4 width rather than PageSetup.PageWidth: assigning
        // PageFormat alone leaves PageWidth empty until render time, so the
        // tab stop came out at zero and the page number sat against the text
        // instead of on the right margin.
        var printable = Unit.FromCentimeter(21.0) - section.PageSetup.LeftMargin - section.PageSetup.RightMargin;
        footer.Format.TabStops.AddTabStop(printable, TabAlignment.Right);

        // Who to call, when the organization has said. It is the line a client
        // needs most, and a document that says a problem is urgent without
        // saying who to tell is a document that gets filed.
        if (report.ContactBlock is { Length: > 0 } contact)
        {
            var reach = section.Footers.Primary.AddParagraph(OneLine(contact));
            reach.Format.Font.Size = 7;
            reach.Format.Font.Color = Muted;
            reach.Format.SpaceBefore = 1;
        }
    }

    /// <summary>
    /// A block of text as one line. The contact block is a textarea, and a
    /// newline inside a MigraDoc paragraph is a literal control character
    /// rather than a break.
    /// </summary>
    private static string OneLine(string text) =>
        string.Join(" · ", text.Split(Breaks, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static readonly char[] Breaks = ['\r', '\n'];

    private static void Header(Section section, ClientReport report)
    {
        Logo(section, report);

        var eyebrow = section.AddParagraph("EMAIL AUTHENTICATION REPORT");
        eyebrow.Format.Font.Size = 7.5;
        eyebrow.Format.Font.Bold = true;
        eyebrow.Format.Font.Color = Muted;
        eyebrow.Format.SpaceAfter = 2;

        var title = section.AddParagraph(report.ClientName);
        title.Format.Font.Size = 22;
        title.Format.Font.Bold = true;
        title.Format.SpaceAfter = 2;

        var period = section.AddParagraph($"{report.Period.Label} · prepared by {report.ProviderName}");
        period.Format.Font.Color = Muted;
        period.Format.Borders.Bottom.Width = 1;
        period.Format.Borders.Bottom.Color = Accent(report) ?? Ink;
        period.Format.SpaceAfter = 14;
    }

    /// <summary>
    /// The organization's colour, when it has set one and it is a plain hex.
    /// </summary>
    /// <remarks>
    /// Checked here as well as where it is stored. This one is drawn rather
    /// than interpolated into a stylesheet, so a bad value is a crash at
    /// render time rather than an injection - which is still a report that
    /// did not go out.
    /// </remarks>
    private static Color? Accent(ClientReport report)
    {
        if (report.BrandColor is not { Length: 7 } hex || hex[0] != '#') { return null; }

        return byte.TryParse(hex.AsSpan(1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var r)
            && byte.TryParse(hex.AsSpan(3, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var g)
            && byte.TryParse(hex.AsSpan(5, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b)
                ? new Color(r, g, b)
                : null;
    }

    /// <summary>
    /// The organization's logo, when it has one this can draw.
    /// </summary>
    /// <remarks>
    /// White-labelling is the point of it: the report is the part of this
    /// product a customer sees, and it should carry the MSP's mark, not this
    /// product's.
    ///
    /// PNG and JPEG only. The store also accepts GIF, WebP and SVG because a
    /// browser draws them in the sidebar, and PDFsharp does not - so an
    /// organization with an SVG logo gets a report with its name on it rather
    /// than an exception where the month's report should be.
    /// </remarks>
    private static void Logo(Section section, ClientReport report)
    {
        if (report.BrandLogo is not { Length: > 0 } url) { return; }
        if (!DmarcMonitor.Core.Tenancy.OrganizationBrand.IsValidLogo(url)) { return; }

        var comma = url.IndexOf(',', StringComparison.Ordinal);
        if (comma < 0) { return; }

        var type = url.AsSpan(0, comma);
        if (!type.StartsWith("data:image/png", StringComparison.Ordinal)
            && !type.StartsWith("data:image/jpeg", StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            var image = section.AddImage("base64:" + url[(comma + 1)..]);
            image.Height = Unit.FromCentimeter(1.1);
            image.LockAspectRatio = true;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or NotSupportedException or FormatException)
        {
            // A logo that will not decode is not a reason to withhold the
            // month's report from a client.
        }
    }

    private static void Verdict(Section section, ClientReport report)
    {
        var label = section.AddParagraph("WHERE THIS STANDS");
        label.Format.Font.Size = 7.5;
        label.Format.Font.Bold = true;
        label.Format.Font.Color = Muted;
        label.Format.SpaceAfter = 3;

        var verdict = section.AddParagraph(report.Verdict);
        verdict.Format.Font.Size = 12.5;
        verdict.Format.SpaceAfter = 14;
        verdict.Format.Borders.Left.Width = 3;
        verdict.Format.Borders.Left.Color = report.StrugglingDomains.Count > 0 ? Bad : Good;
        verdict.Format.LeftIndent = Unit.FromCentimeter(0.35);
    }

    private static void Figures(Section section, ClientReport report)
    {
        if (report.Messages == 0) { return; }

        var enforcing = report.Domains.Count(d => d.IsEnforcing);
        var unproven = report.ImpersonatingSources.Sum(s => s.Failing);

        var table = Grid(section, [4.2, 4.2, 4.2, 4.2]);
        var values = table.AddRow();
        var labels = table.AddRow();

        Figure(values[0], labels[0], $"{report.PassRate:0.#}%", "of your mail is provably yours",
               report.PassRate >= ClientReport.HealthyPassRate ? Good : Bad);
        Figure(values[1], labels[1], $"{enforcing} of {report.Domains.Count}", "domain(s) protected", Ink);
        Figure(values[2], labels[2], $"{unproven:N0}", "message(s) nobody can account for",
               unproven > 0 ? Bad : Good);
        Figure(values[3], labels[3],
               report.HasComparison ? $"{report.PreviousPassRate:0.#}%" : "—",
               report.HasComparison ? $"last month ({report.Period.PreviousLabel})" : "no month to compare",
               Ink);

        section.AddParagraph().Format.SpaceAfter = 10;
    }

    private static void Figure(Cell value, Cell label, string figure, string caption, Color colour)
    {
        var big = value.AddParagraph(figure);
        big.Format.Font.Size = 17;
        big.Format.Font.Bold = true;
        big.Format.Font.Color = colour;
        big.Format.SpaceAfter = 1;

        var small = label.AddParagraph(caption);
        small.Format.Font.Size = 8;
        small.Format.Font.Color = Muted;
    }

    private static void Domains(Section section, ClientReport report)
    {
        if (report.Domains.Count == 0) { return; }

        Heading(section, "Your domains");
        Note(section, "A domain is protected once mail that fails the checks is refused or sent to junk by "
                    + "the receiving provider. Aligned means the check was about your domain rather than the "
                    + "sender's own, which is the only kind DMARC counts. A message is yours if either one "
                    + "aligns, so the two columns can differ widely with every message still protected.");

        var table = Grid(section, [4.6, 2.0, 2.0, 2.0, 2.0, 4.4]);
        HeaderRow(table, ["Domain", "Messages", "Yours", "SPF aligned", "DKIM aligned", "What to do"]);

        foreach (var domain in report.Domains)
        {
            var row = table.AddRow();
            row.Borders.Bottom.Width = 0.5;
            row.Borders.Bottom.Color = Rule;

            var name = row[0].AddParagraph(domain.Domain);
            name.Format.Font.Bold = true;
            name.Format.Font.Size = 8.5;

            var policy = row[0].AddParagraph(domain.Record);
            policy.Format.Font.Size = 7;
            policy.Format.Font.Color = Muted;

            Value(row[1], domain.Messages == 0 ? "—" : domain.Messages.ToString("N0", CultureInfo.InvariantCulture));
            Value(row[2], domain.Messages == 0 ? "—" : $"{domain.PassRate:0.#}%",
                  domain.IsStruggling ? Bad : Ink);
            Value(row[3], domain.Messages == 0 ? "—" : $"{domain.SpfAlignedRate:0.#}%");
            Value(row[4], domain.Messages == 0 ? "—" : $"{domain.DkimAlignedRate:0.#}%");

            var todo = row[5].AddParagraph(domain.Recommended);
            todo.Format.Font.Size = 8;
        }

        section.AddParagraph().Format.SpaceAfter = 8;
    }

    private static void Senders(Section section, ClientReport report)
    {
        if (report.Sources.Count == 0) { return; }

        Heading(section, "Everything sending as you");
        Note(section, "Each row is a group of senders. If you do not recognise something in the second or "
                   + "third row, that is the thing to tell us about.");

        var table = Grid(section, [6.0, 2.2, 2.6, 6.2]);
        HeaderRow(table, ["Group", "Senders", "Messages", "What it means"]);

        foreach (var (which, meaning) in Groups())
        {
            var rows = report.InventoryOf(which);
            if (rows.Count == 0) { continue; }

            var row = table.AddRow();
            row.Borders.Bottom.Width = 0.5;
            row.Borders.Bottom.Color = Rule;

            var label = row[0].AddParagraph(Label(which));
            label.Format.Font.Bold = true;
            label.Format.Font.Size = 8.5;

            Value(row[1], rows.Count.ToString(CultureInfo.InvariantCulture));
            Value(row[2], rows.Sum(r => r.Messages).ToString("N0", CultureInfo.InvariantCulture));

            var note = row[3].AddParagraph(meaning);
            note.Format.Font.Size = 8;
        }

        section.AddParagraph().Format.SpaceAfter = 8;
    }

    private static void WhyFailed(Section section, ClientReport report)
    {
        var causes = report.FailureCauses;
        if (causes.Count == 0) { return; }

        Heading(section, "Why mail failed");

        var table = Grid(section, [6.0, 2.6, 8.4]);
        HeaderRow(table, ["Cause", "Messages", "What it is"]);

        foreach (var (cause, messages, meaning) in causes)
        {
            var row = table.AddRow();
            row.Borders.Bottom.Width = 0.5;
            row.Borders.Bottom.Color = Rule;

            var name = row[0].AddParagraph(cause);
            name.Format.Font.Size = 8.5;

            Value(row[1], messages.ToString("N0", CultureInfo.InvariantCulture));

            var note = row[2].AddParagraph(meaning);
            note.Format.Font.Size = 8;
        }

        section.AddParagraph().Format.SpaceAfter = 8;
    }

    private static void Actions(Section section, ClientReport report)
    {
        Heading(section, "What to do next");

        if (report.Remediation.Count == 0)
        {
            // Reachable only with mail in the period and no finding against
            // any of it - the register carries an item of its own for a month
            // nothing was reported in, because an empty register once printed
            // this sentence over a domain at p=none that no receiver had said
            // a word about.
            var clear = section.AddParagraph(
                "Nothing. Every domain is enforcing, its own mail is arriving, and no sender needs correcting.");
            clear.Format.Font.Color = Good;
            return;
        }

        var table = Grid(section, [1.9, 6.0, 4.4, 2.0, 2.7]);
        HeaderRow(table, ["Priority", "Finding", "What to do", "By", "Who"]);

        foreach (var item in report.Remediation)
        {
            var row = table.AddRow();
            row.Borders.Bottom.Width = 0.5;
            row.Borders.Bottom.Color = Rule;

            var priority = row[0].AddParagraph(item.Priority);
            priority.Format.Font.Bold = true;
            priority.Format.Font.Size = 8.5;
            priority.Format.Font.Color = item.Priority switch
            {
                "Critical" => Bad,
                "High" => Warn,
                _ => Ink,
            };

            Small(row[1], item.Finding);
            Small(row[2], item.Action);
            Small(row[3], item.Target);
            Small(row[4], item.Owner);
        }
    }

    /// <summary>
    /// What was watched, and what the policy turned away.
    /// </summary>
    /// <remarks>
    /// The section a healthy month needs. "Nothing to do" is the right answer
    /// and a poor document: it is sent every month to the client who is
    /// happiest with the service, and on its own it reads as an invoice with
    /// no work attached.
    /// </remarks>
    private static void Covered(Section section, ClientReport report)
    {
        if (report.Covered.Count == 0) { return; }

        Heading(section, "What this covered");

        var table = Grid(section, [5.2, 2.4, 9.4]);

        foreach (var fact in report.Covered)
        {
            var row = table.AddRow();
            row.Borders.Bottom.Width = 0.5;
            row.Borders.Bottom.Color = Rule;

            var label = row[0].AddParagraph(fact.Label);
            label.Format.Font.Size = 8.5;

            Value(row[1], fact.Value, fact.Label.StartsWith("Turned away", StringComparison.Ordinal) ? Good : Ink);

            var note = row[2].AddParagraph(fact.Note);
            note.Format.Font.Size = 8;
            note.Format.Font.Color = Muted;
        }
    }

    private static void Explainer(Section section, ClientReport report)
    {
        section.AddParagraph().Format.SpaceAfter = 10;

        var explainer = section.AddParagraph(
            "Every mail provider that received mail claiming to come from your domains reports back on what "
            + $"it saw. This summarises those reports for {report.Period.Label}. It covers mail sent using "
            + "your domain name, by you and by anybody else, which is why the totals can be larger than the "
            + "mail your staff sent.");
        explainer.Format.Font.Size = 8;
        explainer.Format.Font.Color = Muted;
        explainer.Format.Borders.Top.Width = 0.5;
        explainer.Format.Borders.Top.Color = Rule;
        explainer.Format.SpaceBefore = 8;

        var covers = string.Join(", ", report.Domains.Select(d => d.Domain));
        if (covers.Length > 0)
        {
            var scope = section.AddParagraph($"Domains covered: {covers}.");
            scope.Format.Font.Size = 8;
            scope.Format.Font.Color = Muted;
        }

        var generated = section.AddParagraph(
            $"Generated {report.GeneratedAt:d MMMM yyyy} by {report.ProviderName}. "
            + $"Covers {report.Period.Start:d MMM yyyy} to {report.Period.End:d MMM yyyy}.");
        generated.Format.Font.Size = 8;
        generated.Format.Font.Color = Muted;
    }

    // ---- small shared pieces ------------------------------------------------

    private static Table Grid(Section section, double[] widths)
    {
        var table = section.AddTable();
        table.Borders.Width = 0;
        table.TopPadding = 3;
        table.BottomPadding = 3;
        table.RightPadding = 4;

        foreach (var width in widths)
        {
            table.AddColumn(Unit.FromCentimeter(width));
        }

        return table;
    }

    private static void HeaderRow(Table table, string[] headings)
    {
        var row = table.AddRow();
        row.HeadingFormat = true;   // repeats when a table runs over a page
        row.Borders.Bottom.Width = 0.75;
        row.Borders.Bottom.Color = Ink;

        for (var i = 0; i < headings.Length; i++)
        {
            var cell = row[i].AddParagraph(headings[i]);
            cell.Format.Font.Size = 7.5;
            cell.Format.Font.Bold = true;
            cell.Format.Font.Color = Muted;
        }
    }

    private static void Value(Cell cell, string text) => Value(cell, text, Ink);

    private static void Value(Cell cell, string text, Color colour)
    {
        var paragraph = cell.AddParagraph(text);
        paragraph.Format.Font.Size = 8.5;
        paragraph.Format.Font.Color = colour;
        paragraph.Format.Alignment = ParagraphAlignment.Right;
    }

    private static void Small(Cell cell, string text)
    {
        var paragraph = cell.AddParagraph(text);
        paragraph.Format.Font.Size = 8;
    }

    private static void Heading(Section section, string text)
    {
        var heading = section.AddParagraph(text);
        heading.Format.Font.Size = 12;
        heading.Format.Font.Bold = true;
        heading.Format.SpaceBefore = 6;
        heading.Format.SpaceAfter = 4;
        heading.Format.KeepWithNext = true;
    }

    private static void Note(Section section, string text)
    {
        var note = section.AddParagraph(text);
        note.Format.Font.Size = 8;
        note.Format.Font.Color = Muted;
        note.Format.SpaceAfter = 5;
        note.Format.KeepWithNext = true;
    }

    private static string Label(SenderClass which) => which switch
    {
        SenderClass.Approved => "Yours, and correct",
        SenderClass.Misconfigured => "Yours, and needs correcting",
        SenderClass.Unidentified => "Unrecognised, at a known provider",
        SenderClass.Suspicious => "Unrecognised entirely",
        _ => "Stopped sending",
    };

    private static (SenderClass Which, string Meaning)[] Groups() =>
    [
        (SenderClass.Approved, "Authenticating correctly. Nothing to do."),
        (SenderClass.Misconfigured, "Real mail of yours, set up in a way that does not prove it. The mail most likely to go missing."),
        (SenderClass.Unidentified, "Never proved entitled, but run by a provider we recognise. Usually a tool somebody signed up for."),
        (SenderClass.Suspicious, "Never proved entitled, and nothing identifies the operator."),
        (SenderClass.Retired, "Sent last month and not this one. Either retired, or it stopped working quietly."),
    ];
}
