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
    /// <remarks>
    /// Applied per domain. It lives on <see cref="ClientReport"/> because the
    /// report model needs it to pick out the domains that are struggling, and
    /// two copies of a threshold are two thresholds.
    /// </remarks>
    public const double HealthyPassRate = ClientReport.HealthyPassRate;

    public static ReportSummary Summarize(ClientReport report)
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
            // Judged against the domains the forgeries were actually sent
            // as, fully enforcing or not - not against whether ANY domain
            // enforces. A client with acme.com at p=reject and acme.org at
            // p=none was told forgeries of acme.org "were refused", and they
            // had been delivered.
            var targeted = impersonating.SelectMany(s => s.Domains)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(name => report.Domains.FirstOrDefault(d => d.Domain.Equals(name, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            var open = targeted.Where(d => d is null || !d.IsFullyEnforcing).Select(d => d?.Domain).OfType<string>().ToList();
            var allRefused = targeted.Count > 0 && targeted.All(d => d is { IsFullyEnforcing: true });

            points.Add(
                $"{Count(impersonating.Sum(s => s.Failing))} message(s) from {impersonating.Count} source(s) "
                + "were sent by someone who is not you and could not prove otherwise"
                + (allRefused
                    ? ". Because your domains enforce DMARC, they were refused or sent to junk by the "
                      + "receiving mail provider rather than landing in an inbox."
                    : open.Count > 0 && open.Count < targeted.Count
                        ? $". Those sent as {string.Join(", ", open)} were delivered normally, because that "
                          + "domain's policy does not yet refuse them; the rest were refused or sent to junk."
                        : ". Your domains are not yet enforcing against them, so these were delivered normally."));

            var shared = impersonating.Where(s => s.OtherClientsAffected > 0).ToList();
            if (shared.Count > 0)
            {
                // "Customers", not "organizations". An organization is now the
                // company running this install - NRG Tech Services and
                // NextLayerSec are two - and a customer reading that their
                // attacker also hit "other organizations we protect" would
                // reasonably read it as the wrong noun entirely.
                points.Add(
                    $"{shared.Count} of those source(s) {Was(shared.Count)} also seen sending as other customers "
                    + $"{report.ProviderName} protects, which means this is broad activity rather than "
                    + "someone targeting you specifically.");
            }
        }

        // Named before the estate total is allowed to speak for them. A
        // domain losing half its mail inside a client averaging 96.6% is
        // invisible to every figure above this line, and it is the only thing
        // on the page that client needs to know.
        var struggling = report.StrugglingDomains;
        if (struggling.Count > 0)
        {
            points.Add(
                (struggling.Count == 1
                    ? $"{struggling[0].Domain} is the exception: {struggling[0].OwnPassRate}% of its own mail "
                      + $"authenticated, so {Count(struggling[0].OwnFailing)} message(s) may not "
                      + "have arrived."
                    : $"{struggling.Count} of your domains are doing worse than the total above - "
                      + $"{string.Join(", ", struggling.Select(d => $"{d.Domain} at {d.OwnPassRate}%"))} - "
                      + $"so {Count(report.StrugglingMessages)} message(s) may not have arrived.")
                + $" {Opening(report.ProviderName)} is looking at this.");
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

            // Any ONE domain below the line, not the estate's average. An
            // average is the arithmetic that makes a failing domain vanish.
            NeedsAttention = !report.EveryDomainEnforcing
                             || report.StrugglingDomains.Count > 0
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

        // Per domain, never against the estate's average.
        //
        // This is the line that separates this report from the ones it is
        // meant to beat. A competitor's PDF, checked against its own CSV,
        // announced "100% DMARC Compliance" and "0 Total Issues" for a domain
        // where 55 of 496 messages aligned with neither SPF nor DKIM and 51
        // were quarantined. Nobody had to lie: an average did it for them.
        // Three domains at 100%, 100% and 45.5% average 96.6%, which clears
        // any estate-wide threshold while more than half of one domain's mail
        // is not arriving - and it is that client's invoices.
        var struggling = report.StrugglingDomains;
        if (struggling.Count == 1)
        {
            return $"Your domains are protected, but mail sent using {struggling[0].Domain} is failing "
                 + "and may not be arriving.";
        }

        if (struggling.Count > 1)
        {
            return $"Your domains are protected, but {struggling.Count} of them are losing mail that "
                 + "may not be arriving.";
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
