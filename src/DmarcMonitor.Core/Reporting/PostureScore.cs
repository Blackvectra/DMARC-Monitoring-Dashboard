using System.Globalization;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// The window's mail counted three ways at once: aligned, SPF-passing and
/// DKIM-passing.
/// </summary>
/// <remarks>
/// The three are deliberately not a breakdown and do not sum to anything. A
/// message can pass SPF and DKIM and still fail DMARC, which is the single
/// most misread situation in this subject: the checks were about the domain
/// the sending service uses, not the one in the From line a person reads.
///
/// Printed side by side, the gap between the outer two and DMARC IS the
/// finding. 100 / 100 / 2 says a service authenticates perfectly and counts
/// for nothing.
/// </remarks>
public sealed record AuthenticationRates
{
    public long Messages { get; init; }
    public long DmarcPass { get; init; }
    public long SpfPass { get; init; }
    public long DkimPass { get; init; }

    public double DmarcRate => Share(DmarcPass);
    public double SpfRate => Share(SpfPass);
    public double DkimRate => Share(DkimPass);

    /// <summary>True when there was mail to judge at all.</summary>
    public bool HasMail => Messages > 0;

    private double Share(long part) =>
        Messages == 0 ? 0 : Math.Round(part * 100.0 / Messages, 1);
}

/// <summary>
/// One address sending as a client's domain and proving nothing, for the
/// dashboard's threat table.
/// </summary>
public sealed record ThreatSource
{
    public required string SourceIp { get; init; }

    /// <summary>What the address reverses to, or empty. For reading, never for judging.</summary>
    public string ReverseName { get; init; } = "";

    public long Messages { get; init; }
    public string Domain { get; init; } = "";

    /// <summary>Other clients of this organization the same address was seen against.</summary>
    public int OtherClients { get; init; }

    public string Display => ReverseName.Length > 0 ? ReverseName : SourceIp;
    public bool IsNamed => ReverseName.Length > 0;
}

/// <summary>
/// One sending host, named where a reverse lookup found a name.
/// </summary>
/// <remarks>
/// Grouped by address rather than by the domain a service authenticates for,
/// which is the other question and has its own panel. This is "which machines
/// send our mail"; that one is "which services".
/// </remarks>
public sealed record SendingHost
{
    public required string SourceIp { get; init; }
    public string ReverseName { get; init; } = "";
    public long Messages { get; init; }
    public long DmarcPass { get; init; }
    public long SpfPass { get; init; }
    public long DkimPass { get; init; }

    public string Display => ReverseName.Length > 0 ? ReverseName : SourceIp;
    public bool IsNamed => ReverseName.Length > 0;

    public double DmarcRate => Share(DmarcPass);
    public double SpfRate => Share(SpfPass);
    public double DkimRate => Share(DkimPass);

    private double Share(long part) =>
        Messages == 0 ? 0 : Math.Round(part * 100.0 / Messages, 1);
}

/// <summary>
/// One line of the detailed view: an address, the receiver that reported it,
/// the domain it sent as, and what was done about it.
/// </summary>
/// <remarks>
/// Grouped no further than this on purpose. Every summary in the product
/// gathers these rows by one column or another, and the moment somebody
/// disbelieves a summary - which is the moment that matters - they need the
/// rows it was made of.
/// </remarks>
public sealed record DetailRow
{
    public required string SourceIp { get; init; }
    public string ReverseName { get; init; } = "";
    public string Org { get; init; } = "";
    public string Domain { get; init; } = "";

    /// <summary>What the receiver did: none, quarantine or reject.</summary>
    public string Disposition { get; init; } = "none";

    public long Messages { get; init; }
    public long DmarcPass { get; init; }
    public long SpfPass { get; init; }
    public long DkimPass { get; init; }

    public string Display => ReverseName.Length > 0 ? ReverseName : SourceIp;
    public bool IsNamed => ReverseName.Length > 0;

    /// <summary>Passed DMARC: a check passed AND it was about the visible domain.</summary>
    public bool Aligned => Messages > 0 && DmarcPass == Messages;

    /// <summary>
    /// Something verified, but for the wrong domain.
    /// </summary>
    /// <remarks>
    /// The bucket worth its own heading. These are almost always a real
    /// service sending real mail, authenticating perfectly as itself, and
    /// counting for nothing - which is a configuration job rather than a
    /// threat, and reads as a threat in any view that only has two buckets.
    /// </remarks>
    public bool AuthenticatedNotAligned =>
        DmarcPass < Messages && (SpfPass > 0 || DkimPass > 0);

    /// <summary>Neither check passed at all.</summary>
    public bool Invalid => DmarcPass == 0 && SpfPass == 0 && DkimPass == 0;
}

/// <summary>
/// One receiver that reported, and what it saw.
/// </summary>
/// <remarks>
/// Receivers disagree, and the disagreement is the information. Google
/// accepting what Microsoft quarantines usually means a signature surviving
/// one path and not the other, which is invisible in a single total.
/// </remarks>
public sealed record ReportingOrg
{
    public required string Name { get; init; }
    public long Messages { get; init; }
    public long DmarcPass { get; init; }
    public long SpfPass { get; init; }
    public long DkimPass { get; init; }

    /// <summary>How many separate reports this receiver sent in the window.</summary>
    public int Reports { get; init; }

    public double DmarcRate => Share(DmarcPass);
    public double SpfRate => Share(SpfPass);
    public double DkimRate => Share(DkimPass);

    private double Share(long part) =>
        Messages == 0 ? 0 : Math.Round(part * 100.0 / Messages, 1);
}

/// <summary>
/// One number for the top of the dashboard, and the four things it is made of.
/// </summary>
/// <remarks>
/// <para>
/// Every product in this market puts a score at the top of its dashboard and
/// none of them says what it means, so the number is worth exactly as much as
/// the explanation beside it. This one is written down here, computed from
/// figures already on the page, and every part of it is something an operator
/// can move.
/// </para>
/// <para>
/// Four parts, because there are four ways an estate is actually unsafe:
/// </para>
/// <list type="bullet">
/// <item><b>Enforcement</b> (40) - are the receivers being asked to do
/// anything? A domain at p=none is monitoring, which protects nobody. Scored
/// per domain and averaged, weighted by nothing: a forgotten domain at p=none
/// is exactly the one somebody will forge.</item>
/// <item><b>Alignment</b> (40) - does the real mail pass? Enforcement without
/// this is not protection, it is an outage waiting for the policy to be
/// raised. This is the share of the window's mail that passed DMARC.</item>
/// <item><b>Visibility</b> (10) - are reports arriving? A domain nobody
/// reports on cannot be judged at all, and scoring it as healthy is how a
/// dashboard lies by omission.</item>
/// <item><b>Transport</b> (10) - is the mail encrypted in flight? MTA-STS in
/// enforce mode, which is the only mode that requires anything.</item>
/// </list>
/// <para>
/// A perfect 100 therefore means: every domain enforcing, every message
/// aligned, every domain reporting, every domain requiring TLS. Nothing about
/// it is a curve and nothing about it is generous.
/// </para>
/// </remarks>
public sealed record PostureScore
{
    public const int EnforcementWeight = 40;
    public const int AlignmentWeight = 40;
    public const int VisibilityWeight = 10;
    public const int TransportWeight = 10;

    public double Enforcement { get; init; }
    public double Alignment { get; init; }
    public double Visibility { get; init; }
    public double Transport { get; init; }

    /// <summary>
    /// False when nothing has read DNS, so the transport part is not judged at
    /// all rather than judged as zero.
    /// </summary>
    /// <remarks>
    /// The difference between "nobody requires TLS" and "nobody has looked"
    /// is the whole discipline of this product, and the score broke it: a
    /// fresh install scored 76 and explained itself with "10 of the 10 points
    /// lost to domains not requiring TLS", which blames a customer's
    /// configuration for a reading that was never taken. Two of those domains
    /// were serving enforce at the time.
    /// </remarks>
    public bool TransportKnown { get; init; } = true;

    /// <summary>What the score is out of, once anything unmeasured is left out.</summary>
    private int Possible => TransportKnown ? 100 : 100 - TransportWeight;

    /// <summary>
    /// The whole number shown at the top of the dashboard, out of 100 and
    /// scored only on what is known.
    /// </summary>
    public int Score => (int)Math.Round(
        (Enforcement + Alignment + Visibility + Transport) * 100.0 / Possible,
        MidpointRounding.AwayFromZero);

    /// <summary>
    /// What is not being judged, or empty when everything is.
    /// </summary>
    public string Unassessed =>
        TransportKnown ? "" : "Encryption in transit is not counted yet: nothing has read these domains' DNS.";

    /// <summary>
    /// False when there is nothing to score: no domains, or no mail reported.
    /// </summary>
    /// <remarks>
    /// A fresh install scoring 10 out of 100 is not telling somebody their
    /// estate is unsafe, it is telling them nothing has been imported yet -
    /// and the two look identical on a dial.
    /// </remarks>
    public bool Known { get; init; }

    /// <summary>What to call it in one word.</summary>
    public string Band => Score switch
    {
        >= 90 => "Strong",
        >= 70 => "Reasonable",
        >= 45 => "Needs work",
        _ => "At risk",
    };

    /// <summary>The sentence under the number, naming the largest single loss.</summary>
    public string Weakest
    {
        get
        {
            if (!Known) { return "Not enough reported mail to score yet."; }

            var losses = new List<(string What, double Lost)>
            {
                ("domains not yet enforcing", EnforcementWeight - Enforcement),
                ("mail that does not align", AlignmentWeight - Alignment),
                ("domains sending no reports", VisibilityWeight - Visibility),
            };

            // Only where it was measured. Naming a loss nobody established is
            // the failure this whole type is careful about elsewhere.
            if (TransportKnown) { losses.Add(("domains not requiring TLS", TransportWeight - Transport)); }

            var worst = losses.OrderByDescending(l => l.Lost).First();

            // The all-clear names only what was measured. Claiming "and
            // requiring TLS" where nothing read DNS is the same false
            // statement as blaming the loss on it, said the other way round.
            return worst.Lost < 0.5
                ? TransportKnown
                    ? "Every domain enforcing, aligned, reporting and requiring TLS."
                    : "Every domain enforcing, aligned and reporting."
                : string.Create(CultureInfo.InvariantCulture,
                    $"{worst.Lost:0} of the {Total(worst.What)} points lost to {worst.What}.");
        }
    }

    private static int Total(string what) => what switch
    {
        "domains not yet enforcing" => EnforcementWeight,
        "mail that does not align" => AlignmentWeight,
        "domains sending no reports" => VisibilityWeight,
        _ => TransportWeight,
    };

    /// <summary>
    /// Scores an estate from what the pages already show.
    /// </summary>
    /// <param name="enforcing">Domains whose policy is quarantine or reject.</param>
    /// <param name="domains">Domains in scope.</param>
    /// <param name="reporting">Domains that sent any mail in the window.</param>
    /// <param name="tlsEnforcing">Domains serving an MTA-STS policy in enforce mode.</param>
    /// <param name="rates">The window's authentication results.</param>
    /// <param name="dnsRead">
    /// How many of those domains anything has read the DNS of. Zero means the
    /// transport part is unmeasured, and it is then left out of the score
    /// rather than counted as a failure.
    /// </param>
    public static PostureScore For(
        int enforcing, int domains, int reporting, int tlsEnforcing, AuthenticationRates rates, int dnsRead = -1)
    {
        ArgumentNullException.ThrowIfNull(rates);

        if (domains <= 0 || !rates.HasMail)
        {
            // Partial credit for a policy on a domain nobody has reported on
            // would be a score built out of DNS alone, which is what the
            // records say rather than what the mail does.
            return new PostureScore { Known = false };
        }

        // A negative dnsRead is a caller that does not know, which keeps the
        // old meaning: score it and say nothing.
        var transportKnown = dnsRead != 0;

        return new PostureScore
        {
            Known = true,
            TransportKnown = transportKnown,
            Enforcement = EnforcementWeight * Clamp(enforcing / (double)domains),
            Alignment = AlignmentWeight * Clamp(rates.DmarcRate / 100.0),
            Visibility = VisibilityWeight * Clamp(reporting / (double)domains),
            Transport = transportKnown ? TransportWeight * Clamp(tlsEnforcing / (double)domains) : 0,
        };
    }

    private static double Clamp(double share) => Math.Clamp(share, 0, 1);
}
