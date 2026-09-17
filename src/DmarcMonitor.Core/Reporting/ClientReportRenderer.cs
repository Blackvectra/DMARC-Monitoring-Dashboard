using System.Globalization;
using System.Net;
using System.Text;

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
        Domains(html, report);
        Impersonation(html, report);
        Misconfigured(html, report);
        Legitimate(html, report);
        Changes(html, report);
        Footer(html, report);

        html.Append("</main>\n</body>\n</html>\n");
        return html.ToString();
    }

    // ---- sections -----------------------------------------------------------

    private static void Header(StringBuilder html, ClientReport report) =>
        html.Append(CultureInfo.InvariantCulture, $"""
            <header>
              <p class="eyebrow">Email Protection Report</p>
              <h1>{E(report.ClientName)}</h1>
              <p class="period">{E(report.Period.Label)} &middot; prepared by {E(report.ProviderName)}</p>
            </header>

            """);

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
            var status = d.Policy switch
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

        html.Append("    </tbody>\n  </table>\n</section>\n\n");
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
            // Both figures, because "1 at risk" on its own reads as a service
            // that sent one message rather than one that mostly works.
            html.Append(CultureInfo.InvariantCulture, $"""
                    <tr class="warn">
                      <td class="mono">{E(s.SourceIp)}</td>
                      <td class="n">{N(s.Messages)}</td>
                      <td class="n">{N(s.Failing)}</td>
                      <td class="mono">{E(s.AuthenticatedFor)}</td>
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
            </footer>

            """);

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
        * { box-sizing: border-box; }
        body { margin:0; padding:24px 16px; background:#f6f7f9; color:var(--ink);
               font:16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
        main { max-width:860px; margin:0 auto; background:#fff; padding:40px;
               border:1px solid var(--line); border-radius:10px; }
        header { border-bottom:2px solid var(--ink); padding-bottom:20px; margin-bottom:28px; }
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
