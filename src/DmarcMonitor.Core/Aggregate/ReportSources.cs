using DmarcMonitor.Core.Domains;

namespace DmarcMonitor.Core.Aggregate;

/// <summary>What one sending source in one report turned out to be.</summary>
public enum SourceOutcome
{
    /// <summary>Nothing from this source failed.</summary>
    Authenticated,

    /// <summary>The receiver declined to apply the policy: a forwarder or a list.</summary>
    Forwarded,

    /// <summary>
    /// A DKIM signature verified, over a domain DMARC would not accept here.
    /// </summary>
    SignedForAnotherDomain,

    /// <summary>
    /// SPF passed for an envelope domain that does not align, and no signature
    /// verified.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="SignedForAnotherDomain"/> because the advice
    /// differs. A relay passing SPF for its own envelope is how relays work;
    /// there is no signature to re-issue, and telling somebody to ask the
    /// sender to "sign as you instead" is advice they cannot act on.
    /// </remarks>
    PassedSpfForAnotherDomain,

    /// <summary>Nothing proved anything. A service nobody recorded, or a forger.</summary>
    Unauthenticated,
}

/// <summary>One sending source in one report, with its failure diagnosed.</summary>
public sealed record SourceExplanation
{
    public required string SourceIp { get; init; }

    /// <summary>The domain the recipient saw, which is what alignment is judged against.</summary>
    public required string HeaderFrom { get; init; }

    public long Messages { get; init; }
    public long Passing { get; init; }
    public long Failing => Messages - Passing;

    public SourceOutcome Outcome { get; init; }

    /// <summary>Signatures that verified and did not align.</summary>
    public IReadOnlyList<UnalignedSignature> UnalignedDkim { get; init; } = [];

    /// <summary>Envelope domains SPF passed for that did not align.</summary>
    public IReadOnlyList<string> UnalignedSpf { get; init; } = [];

    /// <summary>True when relaxing the domain's own alignment would fix this.</summary>
    public bool WouldAlignIfRelaxed => UnalignedDkim.Any(u => u.WouldAlignIfRelaxed);
}

/// <summary>
/// Turns a report's rows into one diagnosis per sending source.
/// </summary>
/// <remarks>
/// <para>
/// Extracted so the command line and the domain page decide this the same way.
/// They did not. The command line carried its own alignment helper that was
/// wrong in three ways, and because it is the one tool that works the moment
/// somebody is handed a report, it was wrong at the moment it mattered most.
/// </para>
/// <para>
/// It ignored the published alignment mode, so a domain at <c>adkim=s</c>
/// whose sender signs a subdomain of it was told nothing had authenticated at
/// all - the opposite of the truth, and a diagnosis that sends somebody to look
/// for a missing key that is not missing.
/// </para>
/// <para>
/// It read every authentication result without checking whether it had
/// passed, so a signature that FAILED for a vendor's domain was reported as
/// "authentication succeeded, but for the vendor".
/// </para>
/// <para>
/// And it merged SPF with DKIM, so a relay's ordinary SPF pass drew the advice
/// meant for a vendor signing its own domain.
/// </para>
/// </remarks>
public static class ReportSources
{
    public static IReadOnlyList<SourceExplanation> Describe(AggregateReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var strictDkim = report.Policy.Adkim == AlignmentMode.Strict;
        var strictSpf = report.Policy.Aspf == AlignmentMode.Strict;

        return
        [
            .. report.Records
                .GroupBy(r => r.SourceIp, StringComparer.Ordinal)
                .Select(g => Describe(g, report.Policy.Domain, strictDkim, strictSpf))
                // Problems first, then the loudest of them. A clean source is
                // the one thing nobody needs to read.
                .OrderBy(s => s.Outcome == SourceOutcome.Authenticated)
                .ThenByDescending(s => s.Failing)
                .ThenByDescending(s => s.Messages),
        ];
    }

    private static SourceExplanation Describe(
        IEnumerable<ReportRecord> rows, string policyDomain, bool strictDkim, bool strictSpf)
    {
        var records = rows.ToList();
        var messages = records.Sum(r => (long)r.Count);
        var passing = records.Where(r => r.IsDmarcPass).Sum(r => (long)r.Count);

        // The From domain the recipient saw. Falls back to the domain the
        // policy was published for, which is what a report omitting it means.
        var from = records.Select(r => r.HeaderFrom).FirstOrDefault(h => !string.IsNullOrWhiteSpace(h))
            ?? policyDomain;

        var failing = records.Where(r => !r.IsDmarcPass).ToList();

        // Only signatures that actually VERIFIED, and only on the rows that
        // failed. A signature that did not verify is a different fault with a
        // different fix, and reporting it as a domain mismatch sends somebody
        // to the vendor's alignment settings where they will find nothing.
        var dkim = failing
            .SelectMany(r => r.DkimResults)
            .Where(a => a.IsPass)
            .Select(a => a.Domain)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => (Domain: d.Trim().TrimEnd('.').ToLowerInvariant(), Verdict: Alignment.Classify(d, from)))
            .Where(x => x.Verdict != AlignmentVerdict.Exact)
            .DistinctBy(x => x.Domain, StringComparer.Ordinal)
            .Select(x => new UnalignedSignature(
                x.Domain, x.Verdict,
                WouldAlignIfRelaxed: x.Verdict == AlignmentVerdict.Organizational && strictDkim))
            .ToList();

        // A helo-scoped SPF pass never contributes to DMARC alignment, so it is
        // not evidence of anything here - RFC 7489 §3.1.1.
        var spf = failing
            .SelectMany(r => r.SpfResults)
            .Where(a => Passed(a.Result) && !IsHelo(a))
            .Select(a => a.Domain)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().TrimEnd('.').ToLowerInvariant())
            .Where(d => !Alignment.Aligns(d, from, strictSpf))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var outcome =
            messages == passing ? SourceOutcome.Authenticated
            : failing.Any(r => r.WasOverridden) ? SourceOutcome.Forwarded
            : dkim.Count > 0 ? SourceOutcome.SignedForAnotherDomain
            : spf.Count > 0 ? SourceOutcome.PassedSpfForAnotherDomain
            : SourceOutcome.Unauthenticated;

        return new SourceExplanation
        {
            SourceIp = records[0].SourceIp,
            HeaderFrom = from,
            Messages = messages,
            Passing = passing,
            Outcome = outcome,
            UnalignedDkim = dkim,
            UnalignedSpf = spf,
        };
    }

    private static bool Passed(string? result) =>
        string.Equals(result?.Trim(), "pass", StringComparison.OrdinalIgnoreCase);

    private static bool IsHelo(AuthResult result) =>
        string.Equals(result.Scope?.Trim(), "helo", StringComparison.OrdinalIgnoreCase);
}
