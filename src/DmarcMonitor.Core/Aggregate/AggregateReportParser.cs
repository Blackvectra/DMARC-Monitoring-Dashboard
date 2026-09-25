using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace DmarcMonitor.Core.Aggregate;

/// <summary>
/// Parses a DMARC aggregate report.
///
/// Written to be tolerant, because real reports vary far more than the RFC
/// schema suggests. Small receivers omit optional elements the large providers
/// always send, some emit namespaced XML, counts arrive as strings with
/// whitespace, and results arrive in mixed case. A parser that is strict about
/// any of that silently drops a receiver's entire view of a domain.
///
/// Tolerant does NOT mean guessing. A report that cannot be read is reported
/// as a failure with a reason, never as an empty-but-successful result: an
/// empty report and an unparseable one mean opposite things to an operator.
/// </summary>
public static class AggregateReportParser
{
    /// <summary>
    /// Parses report XML.
    /// </summary>
    /// <remarks>
    /// This input arrives as an email attachment from anyone on the internet,
    /// so DTD processing is disabled outright. Left on, a crafted report can
    /// read local files or hang the process on an entity-expansion bomb. The
    /// PowerShell prototype used a bare [xml] cast, which does not do this.
    /// </remarks>
    public static ParseResult Parse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return ParseResult.Failed("The report was empty.");
        }

        XDocument doc;
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,          // no external entity resolution, ever
                IgnoreWhitespace = true,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                MaxCharactersFromEntities = 0,
            };

            using var stringReader = new StringReader(xml);
            using var reader = XmlReader.Create(stringReader, settings);
            doc = XDocument.Load(reader);
        }
        catch (XmlException ex)
        {
            return ParseResult.Failed($"The report is not valid XML: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            return ParseResult.Failed($"The report could not be read: {ex.Message}");
        }

        var feedback = doc.Root;
        if (feedback is null || !NameIs(feedback, "feedback"))
        {
            return ParseResult.Failed(
                "The file is XML but not a DMARC aggregate report: the root element is " +
                $"'{feedback?.Name.LocalName ?? "missing"}' rather than 'feedback'.");
        }

        var metaEl = Child(feedback, "report_metadata");
        var policyEl = Child(feedback, "policy_published");
        if (policyEl is null)
        {
            // Without policy_published there is no domain, so the report cannot
            // be attributed to anyone. That is not something to paper over.
            return ParseResult.Failed("The report has no policy_published element, so it cannot be attributed to a domain.");
        }

        var domain = Text(Child(policyEl, "domain"));
        if (string.IsNullOrWhiteSpace(domain))
        {
            return ParseResult.Failed("The report's policy_published element has no domain.");
        }

        var metadata = new ReportMetadata
        {
            OrgName = Text(Child(metaEl, "org_name")),
            Email = Text(Child(metaEl, "email")),
            ReportId = Text(Child(metaEl, "report_id")),
            Begin = EpochSeconds(Text(Child(Child(metaEl, "date_range"), "begin"))),
            End = EpochSeconds(Text(Child(Child(metaEl, "date_range"), "end"))),
        };

        var policy = new PolicyPublished
        {
            Domain = NormalizeDomain(domain),
            P = ParsePolicy(Text(Child(policyEl, "p"))) ?? DmarcPolicy.None,
            Sp = ParsePolicy(Text(Child(policyEl, "sp"))),
            Pct = ParsePct(Text(Child(policyEl, "pct"))),
            Adkim = ParseAlignment(Text(Child(policyEl, "adkim"))),
            Aspf = ParseAlignment(Text(Child(policyEl, "aspf"))),
            Np = ParsePolicy(Text(Child(policyEl, "np"))),
            Fo = Text(Child(policyEl, "fo")),
        };

        var records = new List<ReportRecord>();
        foreach (var recEl in Children(feedback, "record"))
        {
            var rec = ParseRecord(recEl);
            if (rec is not null) { records.Add(rec); }
        }

        return ParseResult.Succeeded(new AggregateReport
        {
            Metadata = metadata,
            Policy = policy,
            Records = records,
        });
    }

    private static ReportRecord? ParseRecord(XElement recEl)
    {
        var rowEl = Child(recEl, "row");
        var sourceIp = Text(Child(rowEl, "source_ip"));

        // A row with no source IP describes mail from nowhere. It cannot be
        // attributed, acted on, or explained, so it is dropped rather than
        // shown to an operator as a mystery.
        //
        // Nor one whose address is not an address. Reports are
        // unauthenticated - anybody can mail one to an rua address - and
        // stored as typed, "0.0.0.0/0" or two addresses with a newline between
        // them went everywhere a source goes, including the indicator export a
        // firewall reads. See IpText.
        if (string.IsNullOrWhiteSpace(sourceIp) || !IpText.TryParse(sourceIp, out _)) { return null; }

        var evalEl = Child(rowEl, "policy_evaluated");
        var identEl = Child(recEl, "identifiers");
        var authEl = Child(recEl, "auth_results");

        var overrides = new List<PolicyOverride>();
        foreach (var reasonEl in Children(evalEl, "reason"))
        {
            overrides.Add(new PolicyOverride
            {
                Type = ParseOverride(Text(Child(reasonEl, "type"))),
                Comment = Text(Child(reasonEl, "comment")),
            });
        }

        var spfResults = new List<AuthResult>();
        foreach (var el in Children(authEl, "spf"))
        {
            var d = NormalizeDomain(Text(Child(el, "domain")));
            if (string.IsNullOrEmpty(d)) { continue; }
            spfResults.Add(new AuthResult
            {
                Domain = d,
                Result = Text(Child(el, "result")),
                Scope = Text(Child(el, "scope")),
            });
        }

        // Receivers really do emit empty <dkim><domain/><result/></dkim>
        // elements, several per record. Skipping them is not tidying up: an
        // AuthResult with no domain cannot be aligned against anything and
        // would show in a report as an unexplained blank row.
        var dkimResults = new List<AuthResult>();
        foreach (var el in Children(authEl, "dkim"))
        {
            var d = NormalizeDomain(Text(Child(el, "domain")));
            if (string.IsNullOrEmpty(d)) { continue; }
            dkimResults.Add(new AuthResult
            {
                Domain = d,
                Result = Text(Child(el, "result")),
                Selector = Text(Child(el, "selector")),
            });
        }

        return new ReportRecord
        {
            SourceIp = sourceIp.Trim(),
            Count = ParseCount(Text(Child(rowEl, "count"))),
            Disposition = ParseDisposition(Text(Child(evalEl, "disposition"))),
            Dkim = ParseDmarcResult(Text(Child(evalEl, "dkim"))),
            Spf = ParseDmarcResult(Text(Child(evalEl, "spf"))),
            Overrides = overrides,
            HeaderFrom = NormalizeDomain(Text(Child(identEl, "header_from"))),
            EnvelopeFrom = NormalizeDomain(Text(Child(identEl, "envelope_from"))),
            EnvelopeTo = NormalizeDomain(Text(Child(identEl, "envelope_to"))),
            SpfResults = spfResults,
            DkimResults = dkimResults,
        };
    }

    // ---- element access -----------------------------------------------------
    // Namespace-agnostic: some receivers emit a default namespace and matching
    // on the fully-qualified name would silently find nothing at all.

    private static bool NameIs(XElement el, string name) =>
        string.Equals(el.Name.LocalName, name, StringComparison.OrdinalIgnoreCase);

    private static XElement? Child(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => NameIs(e, name));

    private static IEnumerable<XElement> Children(XElement? parent, string name) =>
        parent?.Elements().Where(e => NameIs(e, name)) ?? [];

    private static string Text(XElement? el) => el?.Value?.Trim() ?? "";

    /// <summary>
    /// Lower-cases and strips the root dot.
    /// </summary>
    /// <remarks>
    /// Real reports contain fully-qualified names with a trailing dot:
    /// gosecure.net sends "nrgtechservices.com." in an spf auth result. Left
    /// as-is, that never matches "nrgtechservices.com" when alignment is
    /// checked, so a domain that authenticated for itself would be reported
    /// as authenticating for somebody else. Found by running the parser
    /// against real mail rather than against XML written to match it.
    /// </remarks>
    private static string NormalizeDomain(string raw) =>
        raw.Trim().TrimEnd('.').ToLowerInvariant();

    // ---- value parsing ------------------------------------------------------

    private static int ParseCount(string raw)
    {
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) { return 0; }
        // A negative count is corrupt input, not a credit against the total.
        return n < 0 ? 0 : n;
    }

    private static int ParsePct(string raw)
    {
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) { return 100; }
        return Math.Clamp(n, 0, 100);
    }

    private static DmarcPolicy? ParsePolicy(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "none" => DmarcPolicy.None,
        "quarantine" => DmarcPolicy.Quarantine,
        "reject" => DmarcPolicy.Reject,
        _ => null,
    };

    private static AlignmentMode ParseAlignment(string raw) =>
        string.Equals(raw.Trim(), "s", StringComparison.OrdinalIgnoreCase)
            ? AlignmentMode.Strict
            : AlignmentMode.Relaxed;

    private static Disposition ParseDisposition(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "quarantine" => Disposition.Quarantine,
        "reject" => Disposition.Reject,
        _ => Disposition.None,
    };

    /// <summary>
    /// Anything that is not an explicit pass is a failure. Treating a blank or
    /// unrecognized value as a pass would inflate the one number an operator
    /// repeats to other people.
    /// </summary>
    private static DmarcResult ParseDmarcResult(string raw) =>
        string.Equals(raw.Trim(), "pass", StringComparison.OrdinalIgnoreCase)
            ? DmarcResult.Pass
            : DmarcResult.Fail;

    private static OverrideReason ParseOverride(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "forwarded" => OverrideReason.Forwarded,
        "sampled_out" => OverrideReason.SampledOut,
        "trusted_forwarder" => OverrideReason.TrustedForwarder,
        "mailing_list" => OverrideReason.MailingList,
        "local_policy" => OverrideReason.LocalPolicy,
        "other" => OverrideReason.Other,
        _ => OverrideReason.Unknown,
    };

    private static DateTimeOffset EpochSeconds(string raw)
    {
        if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var s))
        {
            try { return DateTimeOffset.FromUnixTimeSeconds(s); }
            catch (ArgumentOutOfRangeException) { /* absurd timestamp; fall through */ }
        }
        // Some receivers send an ISO timestamp instead of epoch seconds.
        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
        {
            return dto;
        }
        return DateTimeOffset.MinValue;
    }
}

/// <summary>
/// The outcome of a parse. An unreadable report and an empty one mean opposite
/// things, so they are never collapsed into the same value.
/// </summary>
public sealed record ParseResult
{
    public bool Success { get; private init; }
    public AggregateReport? Report { get; private init; }
    public string Error { get; private init; } = "";

    public static ParseResult Succeeded(AggregateReport report) =>
        new() { Success = true, Report = report };

    public static ParseResult Failed(string error) =>
        new() { Success = false, Error = error };
}
