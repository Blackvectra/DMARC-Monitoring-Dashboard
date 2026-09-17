using System.Globalization;

namespace DmarcMonitor.Core.Reporting;

/// <summary>The opening of a client report: the answer before the evidence.</summary>
public sealed record ReportSummary
{
    /// <summary>One sentence. The thing to read if nothing else is read.</summary>
    public required string Headline { get; init; }

    /// <summary>Supporting points, each already a whole sentence.</summary>
    public IReadOnlyList<string> Points { get; init; } = [];

    /// <summary>True when the month needs the client to do or decide something.</summary>
    public bool NeedsAttention { get; init; }
}

/// <summary>
/// Turns a month of DMARC data into the paragraph a client actually reads.
///
/// Separate from the rendering so the wording can be tested against every
/// shape of month rather than eyeballed in a browser, and so the same
/// sentences can go into HTML now and a PDF or a portal later.
///
/// The bar is that a business owner with no email background can read it and
/// know whether anything is wrong and whether they must do something. That
/// rules out percentages presented without meaning, and it rules out silence
/// about a bad month.
/// </summary>
public static class ReportNarrative
{
    /// <summary>Below this, enough mail is failing to be worth a client's attention.</summary>
    public const double HealthyPassRate = 95;

    public static ReportSummary Summarise(ClientReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        // Nothing arrived. Said plainly, because a report full of zeroes reads
        // like a quiet month rather than like monitoring that has stopped.
        if (report.Messages == 0)
        {
            return new ReportSummary
            {
                Headline = $"No DMARC reports arrived for {report.Period.Label}.",
                NeedsAttention = true,
                Points =
                [
                    "Receiving mail providers send these reports daily, so a month with none usually means "
                        + "one of three things: the DMARC record was changed or removed, the domain stopped "
                        + "sending mail, or the collection on our side stopped.",
                    $"{Opening(report.ProviderName)} is checking all three. No action is needed from you.",
                ],
            };
        }

        var points = new List<string>();
        var impersonating = report.ImpersonatingSources;
        var misconfigured = report.MisconfiguredSources;

        // How much mail, and how much of it was really the client. The first
        // figure anybody asks about.
        points.Add(
            $"{Count(report.Messages)} message(s) were sent using your domain name during {report.Period.Label}, "
            + $"and {report.PassRate}% of them were genuinely yours.");

        if (report.HasComparison)
        {
            points.Add(Comparison(report));
        }

        if (impersonating.Count > 0)
        {
            // No second figure in this sentence. It used to finish with the
            // count of everything acted on across every enforcing domain,
            // introduced as "of those" - which includes the client's OWN
            // misconfigured mail, so the report read "210 of those" directly
            // after naming 137. A number larger than the one it claims to be
            // part of is the kind of thing a client spots immediately, and
            // then nothing else in the document is believed.
            points.Add(
                $"{Count(impersonating.Sum(s => s.Failing))} message(s) from {impersonating.Count} source(s) "
                + "were sent by someone who is not you and could not prove otherwise"
                + (report.Domains.Any(d => d.IsEnforcing)
                    ? ". Because your domains enforce DMARC, they were refused or sent to junk by the "
                      + "receiving mail provider rather than landing in an inbox."
                    : ". Your domains are not yet enforcing, so these were delivered normally."));

            var shared = impersonating.Where(s => s.OtherClientsAffected > 0).ToList();
            if (shared.Count > 0)
            {
                points.Add(
                    $"{shared.Count} of those source(s) {Was(shared.Count)} also seen sending as other organisations "
                    + $"{report.ProviderName} protects, which means this is broad activity rather than "
                    + "someone targeting you specifically.");
            }
        }

        if (misconfigured.Count > 0)
        {
            points.Add(
                $"{misconfigured.Count} service(s) you use {Is(misconfigured.Count)} sending on your behalf without "
                + $"being set up correctly, which put {Count(misconfigured.Sum(s => s.Failing))} of your own "
                + $"message(s) at risk of being rejected. {Opening(report.ProviderName)} is correcting this.");
        }

        if (report.Changes.Count > 0)
        {
            var applied = report.Changes.Count(c => !c.WasRolledBack);
            points.Add($"{applied} change(s) were made to your DNS records this month. They are listed below.");
        }

        return new ReportSummary
        {
            Headline = Headline(report, impersonating.Count > 0, misconfigured.Count > 0),
            Points = points,
            NeedsAttention = !report.EveryDomainEnforcing
                             || report.PassRate < HealthyPassRate
                             || misconfigured.Count > 0,
        };
    }

    private static string Headline(ClientReport report, bool impersonated, bool misconfigured)
    {
        var domains = report.Domains.Count;
        var enforcing = report.Domains.Count(d => d.IsEnforcing);

        // Not protected yet is the most important thing that can be true, so
        // it outranks a good pass rate: a clean month at p=none still means
        // anybody can send as this client and it will be delivered.
        if (enforcing == 0)
        {
            return domains == 1
                ? "Your domain is being monitored, but is not yet protected."
                : $"Your {domains} domains are being monitored, but none is yet protected.";
        }

        if (enforcing < domains)
        {
            return $"{enforcing} of your {domains} domains are protected. The rest are still being monitored.";
        }

        if (report.PassRate < HealthyPassRate)
        {
            return "Your domains are protected, but some of your own mail is failing and may not be arriving.";
        }

        // A misconfigured service can sit below the pass-rate threshold and
        // still be losing real mail. Without this the headline reads "nothing
        // needed attention" directly above a line saying otherwise, and a
        // client who spots that stops trusting the rest of the document.
        if (misconfigured)
        {
            return "Your domains are protected, but a service sending on your behalf needs correcting.";
        }

        return impersonated
            ? "Your domains are protected, and attempts to send mail as you were stopped."
            : "Your domains are protected, and nothing needed attention this month.";
    }

    private static string Comparison(ClientReport report)
    {
        var change = Math.Round(report.PassRate - report.PreviousPassRate, 1);

        // Under a tenth of a point either way is noise, and reporting it as
        // movement invites questions that have no answer.
        if (Math.Abs(change) < 0.1)
        {
            return $"That is unchanged from {report.Period.PreviousLabel}.";
        }

        return change > 0
            ? $"That is up from {report.PreviousPassRate}% in {report.Period.PreviousLabel}."
            : $"That is down from {report.PreviousPassRate}% in {report.Period.PreviousLabel}.";
    }

    private static string Count(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    // The "(s)" convention keeps the counts honest without branching on every
    // noun, but a verb cannot be fudged that way: "1 source(s) were" is the
    // kind of thing a client notices and mentions.
    private static string Was(int count) => count == 1 ? "was" : "were";

    private static string Is(int count) => count == 1 ? "is" : "are";

    /// <summary>
    /// The provider name at the start of a sentence.
    /// </summary>
    /// <remarks>
    /// The default reads "your IT provider", which is right mid-sentence and
    /// wrong as the first word. A real company name is already capitalised, so
    /// this is a no-op for it.
    /// </remarks>
    private static string Opening(string providerName) =>
        string.IsNullOrEmpty(providerName)
            ? providerName
            : char.ToUpperInvariant(providerName[0]) + providerName[1..];
}
