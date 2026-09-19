using System.Globalization;
using System.Net;
using System.Text;
using DmarcMonitor.Core.Charting;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// Renders a client report as one self-contained HTML file.
///
/// Self-contained on purpose: no stylesheet, no script, no image, no font
/// fetched from anywhere. A client opens this from an email attachment, often
/// on a phone, sometimes with no network, and frequently prints it to PDF to
/// forward to an accountant or an auditor. Anything external turns into a
/// broken page at exactly the moment the report is being judged.
///
/// Everything drawn from the database is escaped. That is not cosmetic: the
/// text in a report - organisation names, domains, DNS record values - arrives
/// from whoever sent the report, so it is attacker-influenceable, and pasting
/// it into a page unescaped would be a scripting hole in a document that gets
/// forwarded to the client's own staff.
/// </summary>
public static class ClientReportRenderer
{
    public static string ToHtml(ClientReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var summary = ReportNarrative.Summarise(report);
        var html = new StringBuilder(16 * 1024);

        html.Append(CultureInfo.InvariantCulture, $"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{E(report.ClientName)} - Email Protection Report, {E(report.Period.Label)}</title>
            <style>{Css}</style>
            </head>
            <body>
            <main>
            """);

        Header(html, report);
        Summary(html, summary);
        Trend(html, report);
        Domains(html, report);
        Impersonation(html, report);
        Misconfigured(html, report);
        Legitimate(html, report);
        Changes(html, report);
        Overridden(html, report);
        Footer(html, report);

        html.Append("</main>\n</body>\n</html>\n");
        return html.ToString();
    }

    // ---- sections -----------------------------------------------------------

    private static void Header(StringBuilder html, ClientReport report) =>
        html.Append(CultureInfo.InvariantCulture, $"""
            <header{Brand(report)}>
              {Logo(report)}<p class="eyebrow">Email Protection Report</p>
              <h1>{E(report.ClientName)}</h1>
              <p class="period">{E(report.Period.Label)} &middot; prepared by {E(report.ProviderName)}</p>
            </header>

            """);

    /// <summary>
    /// The organisation's colour on the header rule, when it has one. Only a
    /// value the store validated as a plain hex ever gets here, and it is
    /// checked again because this is interpolated into a style attribute.
    /// </summary>
    private static string Brand(ClientReport report) =>
        report.BrandColor is { } c && System.Text.RegularExpressions.Regex.IsMatch(c, "^#[0-9a-fA-F]{6}$")
            ? $" style=\"border-bottom-color:{c}\""
            : "";

    /// <summary>The logo, when there is one. A data: URL of an image type, checked again before it lands in a src.</summary>
    private static string Logo(ClientReport report) =>
        report.BrandLogo is { } logo && DmarcMonitor.Core.Tenancy.OrganisationBrand.IsValidLogo(logo)
            ? $"<img class=\"logo\" src=\"{logo}\" alt=\"{E(report.ProviderName)}\" />\n              "
            : "";

    private static void Summary(StringBuilder html, ReportSummary summary)
    {
        html.Append(CultureInfo.InvariantCulture, $"""
            <section class="summary {(summary.NeedsAttention ? "attention" : "clear")}">
              <h2>In short</h2>
              <p class="headline">{E(summary.Headline)}</p>
              <ul>

            """);

        foreach (var point in summary.Points)
        {
            html.Append(CultureInfo.InvariantCulture, $"    <li>{E(point)}</li>\n");
        }

        html.Append("  </ul>\n</section>\n\n");
    }

    /// <summary>
    /// The month as a picture.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Inline SVG with no script and no external file, like the rest of this
    /// document: it is mailed, forwarded and printed, and anything fetched
    /// from elsewhere would arrive as a broken image in a client's inbox.
    /// </para>
    /// <para>
    /// A month's total cannot show the shape of the month. A client whose mail
    /// was fine until the 14th and half-rejected since reads as "93%
    /// protected", which is accurate and gives them nothing to act on.
    /// </para>
    /// </remarks>
    private static void Trend(StringBuilder html, ClientReport report)
    {
        // Nothing to draw is not a blank panel: a month with no mail at all is
        // said in words by the summary above, and an empty chart under it
        // reads as a rendering fault.
        if (report.Daily.Count == 0 || report.Daily.All(d => d.Messages == 0)) { return; }

        const double w = 640;
        const double h = 130;

        var totals = report.Daily.Select(d => d.Reported ? (double?)d.Messages : null).ToList();
        var failing = report.Daily.Select(d => d.Reported ? (double?)d.Failing : null).ToList();
        var peak = report.Daily.Where(d => d.Reported).Select(d => d.Messages).DefaultIfEmpty(0).Max();
        var ceiling = peak > 0 ? (double)peak : 1;

        var missing = report.Daily.Count(d => !d.Reported);

        html.Append(CultureInfo.InvariantCulture, $"""
            <section>
              <h2>Your mail, day by day</h2>
              <p class="note">The taller the shape, the more mail you sent that day. The darker band is
                 mail that failed the checks.</p>
              <svg class="trend" viewBox="0 0 {N(w)} {N(h)}" role="img"
                   aria-label="{E($"{report.Messages:N0} messages over {report.Daily.Count} days, {report.PassRate}% protected.")}">
                <path d="{Chart.Area(totals, w, h, ceiling)}" class="t-total" />
                <path d="{Chart.Area(failing, w, h, ceiling)}" class="t-fail" />
                <path d="{Chart.Line(totals, w, h, ceiling)}" class="t-line" />
                {Dots(totals, w, h, ceiling)}
              </svg>
              <p class="axis"><span>{E(report.Daily[0].Day.ToString("d MMM", CultureInfo.InvariantCulture))}</span>
                 <span>peak {peak:N0} a day</span>
                 <span>{E(report.Daily[^1].Day.ToString("d MMM", CultureInfo.InvariantCulture))}</span></p>

            """);

        if (missing > 0)
        {
            // Said rather than drawn flat. A client who sees a dip wants to
            // know whether their mail stopped or the reporting did, and those
            // are very different conversations.
            html.Append(CultureInfo.InvariantCulture, $"""
                  <p class="note">{missing} day(s) in this period have no reports at all, so the line
                     breaks rather than dropping to zero. That usually means the receivers sent nothing,
                     not that your mail stopped.</p>

                """);
        }

        html.Append("</section>\n\n");
    }

    /// <summary>
    /// Readings with no neighbour, drawn as dots.
    /// </summary>
    /// <remarks>
    /// Without these a client heard from on exactly one day of the month gets
    /// an empty rectangle where the chart should be. Found on the real data:
    /// mcleanelectric.com had one reported day in August, so the line was a
    /// single move with nothing to join to and the area had no width. A blank
    /// box in a report going to a customer reads as broken software.
    /// </remarks>
    private static string Dots(IReadOnlyList<double?> values, double w, double h, double ceiling)
    {
        var dots = Chart.IsolatedPoints(values, w, h, ceiling);
        if (dots.Count == 0) { return ""; }

        var svg = new StringBuilder();
        foreach (var (x, y) in dots)
        {
            svg.Append(CultureInfo.InvariantCulture, $"""<circle cx="{N(x)}" cy="{N(y)}" r="3" class="t-dot" />""");
        }
        return svg.ToString();
    }

    private static string N(double value) =>
        value.ToString("0.##", CultureInfo.InvariantCulture);

    private static void Domains(StringBuilder html, ClientReport report)
    {
        if (report.Domains.Count == 0) { return; }

        html.Append("""
            <section>
              <h2>Your domains</h2>
              <p class="note">A domain is <strong>protected</strong> once mail that fails the checks is
              refused or sent to junk by the receiving provider. Until then it is only being watched.</p>
              <table>
                <thead><tr><th>Domain</th><th>Status</th><th class="n">Messages</th><th class="n">Genuinely yours</th></tr></thead>
                <tbody>

            """);

        foreach (var d in report.Domains)
        {
            var status = !d.PolicyKnown
                ? "Not known - no reports had reached us by then"
                : d.Policy switch
                {
                    "reject" => "Protected - failing mail is refused",
                    "quarantine" => "Protected - failing mail goes to junk",
                    _ => "Monitoring only - not yet protected",
                };

            // A domain that sent nothing has no percentage worth printing; 0%
            // would read as total failure rather than as no mail.
            var rate = d.Messages == 0 ? "no mail" : $"{d.PassRate}%";

            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="{(d.IsEnforcing ? "ok" : "warn")}">
                      <td class="mono">{E(d.Domain)}</td>
                      <td>{E(status)}</td>
                      <td class="n">{N(d.Messages)}</td>
                      <td class="n">{E(rate)}</td>
                    </tr>

                """);
        }

        html.Append("    </tbody>\n  </table>\n");
        TransportSecurity(html, report);
        html.Append("</section>\n\n");
    }

    /// <summary>
    /// MTA-STS announced but not enforced.
    /// </summary>
    /// <remarks>
    /// Parsed and stored since the TLS reports were first read, and never put
    /// in front of anybody. A domain in testing mode publishes a policy and a
    /// receiver honours none of it: mail is delivered over a connection that
    /// does not match and the failure is merely reported. The domain looks
    /// protected in transit and is not, which is precisely the gap this
    /// product exists to close.
    /// </remarks>
    private static void TransportSecurity(StringBuilder html, ClientReport report)
    {
        var testing = report.Domains
            .Where(d => string.Equals(d.MtaStsMode, "Testing", StringComparison.OrdinalIgnoreCase))
            .Select(d => d.Domain)
            .ToList();

        if (testing.Count == 0) { return; }

        html.Append(CultureInfo.InvariantCulture, $"""
              <p class="note"><strong>Transport security is not yet switched on.</strong>
              {E(string.Join(", ", testing))} publishes an MTA-STS policy in <em>testing</em> mode, which
              means receiving providers report on connections that do not match it but still deliver the
              mail. Moving to enforcing mode is what makes it take effect.</p>

            """);
    }

    private static void Impersonation(StringBuilder html, ClientReport report)
    {
        var sources = report.ImpersonatingSources;
        if (sources.Count == 0)
        {
            html.Append("""
                <section>
                  <h2>Who tried to send mail as you</h2>
                  <p class="good">Nobody. No source sent mail claiming to be one of your domains without
                  being able to prove it.</p>
                </section>

                """);
            return;
        }

        html.Append("""
            <section>
              <h2>Who tried to send mail as you</h2>
              <p class="note">These sources sent mail using your domain name and could not prove they were
              entitled to. Each is either a service nobody told us about, or somebody pretending to be you.</p>
              <table>
                <thead><tr><th>Source</th><th class="n">Sent</th><th class="n">Unproven</th><th>Sent as</th><th>Also seen elsewhere</th></tr></thead>
                <tbody>

            """);

        foreach (var s in sources)
        {
            var elsewhere = s.OtherClientsAffected > 0
                ? $"Yes - {s.OtherClientsAffected} other organisation(s)"
                : "No";

            // Both figures again. An address that sent twelve messages and
            // could not prove one of them is a different situation from one
            // that sent twelve and could prove none, and the client will read
            // this table looking for exactly that difference.
            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="bad">
                      <td class="mono">{E(s.SourceIp)}</td>
                      <td class="n">{N(s.Messages)}</td>
                      <td class="n">{N(s.Failing)}</td>
                      <td class="mono">{E(string.Join(", ", s.Domains))}</td>
                      <td>{E(elsewhere)}</td>
                    </tr>

                """);
        }

        html.Append("    </tbody>\n  </table>\n</section>\n\n");
    }

    private static void Misconfigured(StringBuilder html, ClientReport report)
    {
        var sources = report.MisconfiguredSources;
        if (sources.Count == 0) { return; }

        html.Append("""
            <section>
              <h2>Your own mail that is at risk</h2>
              <p class="note">These are real services sending on your behalf, set up in a way that does not
              prove the mail is yours. This is your mail, and it is the mail most likely to go missing.</p>
              <table>
                <thead><tr><th>Source</th><th class="n">Sent</th><th class="n">At risk</th><th>Signed as</th></tr></thead>
                <tbody>

            """);

        foreach (var s in sources)
        {
            // Two different things sit in this table. A third-party service
            // names the domain it signs as; one of the client's own paths
            // signs as the client and simply breaks sometimes, and has no
            // other domain to name. An empty cell there reads as missing data
            // rather than as the answer.
            var signedAs = s.Authenticated
                ? $"""<td class="mono">{E(s.AuthenticatedFor)}</td>"""
                : """<td class="muted">your own sending path, signature broken in transit</td>""";

            // Both figures, because "1 at risk" on its own reads as a service
            // that sent one message rather than one that mostly works.
            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="warn">
                      <td class="mono">{E(s.SourceIp)}</td>
                      <td class="n">{N(s.Messages)}</td>
                      <td class="n">{N(s.Failing)}</td>
                      {signedAs}
                    </tr>

                """);
        }

        html.Append("    </tbody>\n  </table>\n</section>\n\n");
    }

    private static void Legitimate(StringBuilder html, ClientReport report)
    {
        var sources = report.LegitimateSources;
        if (sources.Count == 0) { return; }

        html.Append("""
            <section>
              <h2>What sends mail as you</h2>
              <p class="note">Everything below is sending legitimately. If you do not recognise one of these,
              tell us: a service nobody remembers signing up for is worth knowing about.</p>
              <table>
                <thead><tr><th>Source</th><th class="n">Messages</th><th>Domains</th></tr></thead>
                <tbody>

            """);

        // Long tails are common and nobody reads past the first handful; the
        // rest is summarised rather than dropped, so the totals still add up.
        const int Shown = 15;
        foreach (var s in sources.Take(Shown))
        {
            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="ok">
                      <td class="mono">{E(s.SourceIp)}</td>
                      <td class="n">{N(s.Messages)}</td>
                      <td class="mono">{E(string.Join(", ", s.Domains))}</td>
                    </tr>

                """);
        }

        if (sources.Count > Shown)
        {
            var rest = sources.Skip(Shown).ToList();
            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="rest">
                      <td colspan="2">and {N(rest.Count)} more source(s)</td>
                      <td class="n">{N(rest.Sum(s => s.Messages))} message(s)</td>
                    </tr>

                """);
        }

        html.Append("    </tbody>\n  </table>\n</section>\n\n");
    }

    private static void Changes(StringBuilder html, ClientReport report)
    {
        if (report.Changes.Count == 0)
        {
            html.Append("""
                <section>
                  <h2>What we did this month</h2>
                  <p class="note">No changes were needed to your DNS records this month.</p>
                </section>

                """);
            return;
        }

        html.Append("""
            <section>
              <h2>What we did this month</h2>
              <p class="note">Taken from the record of changes actually applied, not written from memory.</p>
              <table>
                <thead><tr><th>Date</th><th>Record</th><th>Why</th><th>Outcome</th></tr></thead>
                <tbody>

            """);

        foreach (var c in report.Changes)
        {
            // A reverted change stays in the report and says so. Removing it
            // would turn a record into a sales document, and a client should
            // hear about a rollback from us rather than discover it.
            var outcome = c.WasRolledBack ? "Reverted" : "Applied";

            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="{(c.WasRolledBack ? "warn" : "ok")}">
                      <td>{E(c.AppliedAt.ToString("d MMM yyyy", CultureInfo.InvariantCulture))}</td>
                      <td class="mono">{E(c.RecordType)} {E(c.RecordName)}</td>
                      <td>{E(c.Reason)}</td>
                      <td>{E(outcome)}</td>
                    </tr>

                """);
        }

        html.Append("    </tbody>\n  </table>\n</section>\n\n");
    }

    /// <summary>
    /// Why the tables do not add up to the headline.
    /// </summary>
    /// <remarks>
    /// A client who totals the source tables and finds them short of the
    /// figure at the top has found something that looks like an error. It is
    /// not, and the difference is worth naming rather than hiding: forwarded
    /// mail breaking authentication is normal and is not a sender anybody
    /// should act on.
    /// </remarks>
    private static void Overridden(StringBuilder html, ClientReport report)
    {
        if (report.OverriddenMessages <= 0) { return; }

        html.Append(CultureInfo.InvariantCulture, $"""
            <section>
              <p class="note">The tables above leave out {N(report.OverriddenMessages)} message(s) that the
              receiving provider handled under its own rules - usually mail forwarded by a mailing list,
              which breaks the checks in a way that is expected and not worth acting on. They are counted
              in the {N(report.Messages)} at the top.</p>
            </section>

            """);
    }

    private static void Footer(StringBuilder html, ClientReport report) =>
        html.Append(CultureInfo.InvariantCulture, $"""
            <section class="explainer">
              <h2>What this report is</h2>
              <p>Every mail provider that received mail claiming to come from your domains reports back on
              what it saw. This summarises every one of those reports for {E(report.Period.Label)}. It covers
              mail sent <em>using your domain name</em>, by you and by anybody else, which is why the totals
              can be larger than the mail your staff sent.</p>
            </section>
            <footer>
              <p>Generated {E(report.GeneratedAt.ToString("d MMMM yyyy", CultureInfo.InvariantCulture))}
              by {E(report.ProviderName)}. Covers {E(report.Period.Start.ToString("d MMM yyyy", CultureInfo.InvariantCulture))}
              to {E(report.Period.End.ToString("d MMM yyyy", CultureInfo.InvariantCulture))}.</p>
              {Contact(report)}
            </footer>

            """);

    /// <summary>Who to call, one paragraph per line, when the organisation said.</summary>
    private static string Contact(ClientReport report) =>
        string.IsNullOrWhiteSpace(report.ContactBlock)
            ? ""
            : "<p class=\"contact\">" + string.Join("<br />", report.ContactBlock.Split('\n').Select(l => E(l.TrimEnd('\r')))) + "</p>";

    // ---- helpers ------------------------------------------------------------

    /// <summary>Escapes anything that came out of the database.</summary>
    private static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string N(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>
    /// Inline because the file has to work as an attachment with no network.
    /// Print rules included: a client forwarding this to an accountant prints
    /// it, and a table split across a page break is unreadable.
    /// </summary>
    private const string Css = """

        :root { --ink:#16191d; --muted:#5b6470; --line:#e2e6eb; --ok:#0d7a45; --warn:#9a6400; --bad:#b3261e; }

        /* The chart. Inline SVG with no script and no external file, because
           this document is mailed, forwarded and printed. */
        .trend { width:100%; height:130px; display:block; margin:10px 0 4px; }
        .t-total { fill:#0d7a45; opacity:.14; }
        .t-fail  { fill:#b3261e; opacity:.32; }
        .t-line  { fill:none; stroke:#0d7a45; stroke-width:1.5; }
        .t-dot   { fill:#0d7a45; }
        .axis { display:flex; justify-content:space-between; gap:10px;
                font-size:12px; color:var(--muted); margin:0 0 6px; }
        * { box-sizing: border-box; }
        body { margin:0; padding:24px 16px; background:#f6f7f9; color:var(--ink);
               font:16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
        main { max-width:860px; margin:0 auto; background:#fff; padding:40px;
               border:1px solid var(--line); border-radius:10px; }
        header { border-bottom:2px solid var(--ink); padding-bottom:20px; margin-bottom:28px; }
        .logo { display:block; max-height:48px; max-width:220px; margin:0 0 14px; }
        .contact { margin:10px 0 0; color:var(--ink); }
        .eyebrow { margin:0; text-transform:uppercase; letter-spacing:.09em; font-size:12px;
                   font-weight:700; color:var(--muted); }
        h1 { margin:6px 0 4px; font-size:30px; line-height:1.2; }
        .period { margin:0; color:var(--muted); }
        h2 { font-size:19px; margin:0 0 10px; }
        section { margin-bottom:32px; }
        .summary { padding:22px 24px; border-radius:8px; border-left:5px solid var(--ok); background:#f2f9f5; }
        .summary.attention { border-left-color:var(--warn); background:#fdf7ec; }
        .headline { font-size:19px; font-weight:600; margin:0 0 12px; }
        .summary ul { margin:0; padding-left:20px; }
        .summary li { margin-bottom:8px; }
        .note { color:var(--muted); font-size:14px; margin:0 0 12px; }
        .good { color:var(--ok); font-weight:600; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line);
                 vertical-align:top; word-break:break-word; }
        th { font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted);
             border-bottom:2px solid var(--line); }
        td.n, th.n { text-align:right; white-space:nowrap; }
        .mono { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; }
        tr.ok td:first-child { border-left:3px solid var(--ok); }
        tr.warn td:first-child { border-left:3px solid var(--warn); }
        tr.bad td:first-child { border-left:3px solid var(--bad); }
        tr.rest td { color:var(--muted); font-style:italic; }
        .explainer { background:#f6f7f9; padding:20px 24px; border-radius:8px; font-size:14px; }
        .explainer h2 { font-size:16px; }
        .explainer p { margin:0; }
        footer { border-top:1px solid var(--line); padding-top:16px; color:var(--muted); font-size:13px; }

        @media print {
          body { background:#fff; padding:0; }
          main { border:0; padding:0; max-width:none; }
          section, tr { break-inside:avoid; }
        }

        """;
}
