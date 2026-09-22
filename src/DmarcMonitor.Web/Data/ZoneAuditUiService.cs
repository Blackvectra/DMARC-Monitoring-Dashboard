using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Tenancy;

namespace DmarcMonitor.Web.Data;

/// <summary>What a pasted zone produced, or why it was not read.</summary>
/// <param name="Report">The audit, or null when nothing was run.</param>
/// <param name="Refused">Why nothing was run, in a sentence for the page.</param>
public sealed record ZoneAuditOutcome(ZoneAuditReport? Report, string? Refused = null);

/// <summary>
/// The paste box on the domain page.
///
/// The one thing an operator can hand this application that it cannot fetch
/// for itself. DNS will not list a domain's DKIM selectors and will not
/// transfer a zone, so the records that have stopped working - and the ones
/// nobody remembers adding - are only visible in an export.
/// </summary>
public sealed class ZoneAuditUiService(DatabaseInfo database, DnsLookup lookup, AuditLog audit)
{
    /// <summary>
    /// The longest paste this will read.
    /// </summary>
    /// <remarks>
    /// A zone file is kilobytes. This exists so that a mis-paste - a log, a
    /// database dump, somebody's clipboard - is declined with a sentence
    /// rather than parsed, and so the circuit's receive limit is never the
    /// thing that says no, because what that looks like from the browser is
    /// the page freezing.
    /// </remarks>
    public const int MaxCharacters = 200_000;

    public async Task<ZoneAuditOutcome> RunAsync(
        string domain, string? text, string? tenantId, string actor, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        if (string.IsNullOrWhiteSpace(text))
        {
            return new ZoneAuditOutcome(null, "Paste the zone file first.");
        }

        if (text.Length > MaxCharacters)
        {
            return new ZoneAuditOutcome(null,
                $"That is {text.Length:N0} characters. Zone files are a few thousand, so this is "
                + "probably not one.");
        }

        // Scoped to the organization being looked at. Without it the audit
        // cross-references the whole book: another organization's DKIM
        // selectors appear in the findings, and its domains change which
        // reporting authorizations are flagged as pointing at a stranger.
        var auditor = new ZoneAuditor(
            lookup, File.Exists(database.Path) ? database.Path : null, tenantId);
        var report = await auditor.RunAsync(text, domain, offline: false, ct).ConfigureAwait(false);

        // Worth a line in the log: it reaches outside the machine, up to fifty
        // DNS queries at a time, and an operator should be able to see who ran
        // it against which customer. The file itself is never written down -
        // it is a complete map of somebody's estate, and the findings are the
        // part worth keeping.
        await audit.RecordAsync(
            tenantId, actor, "zone.audit",
            $"{domain}: {report.Zone.Records.Count} record(s), {report.Findings.Count} finding(s)",
            ct).ConfigureAwait(false);

        return new ZoneAuditOutcome(report);
    }
}
