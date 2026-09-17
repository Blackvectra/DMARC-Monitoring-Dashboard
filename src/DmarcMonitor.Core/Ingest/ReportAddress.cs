using System.Security.Cryptography;
using System.Text;

namespace DmarcMonitor.Core.Ingest;

/// <summary>
/// A per-domain report address, of the form
/// <c>&lt;token&gt;@rua.yourdomain.com</c>.
///
/// Every monitored domain gets its own generated address to publish in its
/// rua= tag, rather than everything arriving at one shared mailbox.
///
/// The reason is a trust boundary, not tidiness. A published rua address is
/// public, and anyone on the internet can send mail to it. If reports are
/// attributed by reading policy_published/domain out of the XML, then a
/// fabricated report claiming to be for a customer's domain is ingested as
/// genuine: their pass rate, their sender list and their enforcement
/// readiness are all quietly poisoned by someone who simply sent an email.
///
/// A secret per-domain address makes the envelope an independent claim about
/// who the report is for. Attribution then requires the address and the
/// report contents to AGREE, which an attacker cannot arrange without
/// knowing an address they were never told.
///
/// Secondary benefits that fall out of the same design: one customer can be
/// revoked without touching any other, onboarding is confirmed the moment
/// mail arrives at a given address, and two customers with similar domain
/// names can never be confused for one another.
/// </summary>
public static class ReportAddress
{
    /// <summary>
    /// Token length in characters. Base32 over 80 bits, which is far beyond
    /// guessing while staying short enough to sit comfortably inside a DNS
    /// TXT record that also has to hold the rest of the DMARC policy.
    /// </summary>
    public const int TokenLength = 16;

    /// <summary>
    /// Crockford-style base32 without I, L, O or U. Ambiguous characters are
    /// excluded because these get read aloud, retyped from a ticket, and
    /// copied into a customer's DNS by hand.
    /// </summary>
    private const string Alphabet = "0123456789abcdefghjkmnpqrstvwxyz";

    /// <summary>
    /// Mints a token with a cryptographic RNG.
    /// </summary>
    /// <remarks>
    /// Not Random: a predictable token is the same as no token at all, since
    /// the whole protection is that an attacker cannot work out the address
    /// for a domain they want to poison.
    /// </remarks>
    public static string GenerateToken()
    {
        var sb = new StringBuilder(TokenLength);
        Span<byte> bytes = stackalloc byte[TokenLength];
        RandomNumberGenerator.Fill(bytes);

        foreach (var b in bytes)
        {
            // 32 divides 256 exactly, so masking introduces no modulo bias.
            sb.Append(Alphabet[b & 0x1F]);
        }
        return sb.ToString();
    }

    /// <summary>Builds the full address to publish in a domain's rua= tag.</summary>
    public static string Build(string token, string reportingDomain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(reportingDomain);

        if (!IsValidToken(token))
        {
            throw new ArgumentException("Token is not in the expected format.", nameof(token));
        }
        return $"{token}@{reportingDomain.Trim().TrimEnd('.').ToLowerInvariant()}";
    }

    public static bool IsValidToken(string? token)
    {
        if (token is null || token.Length != TokenLength) { return false; }
        foreach (var c in token)
        {
            if (!Alphabet.Contains(c, StringComparison.Ordinal)) { return false; }
        }
        return true;
    }

    /// <summary>
    /// Recovers the token from an address a report was delivered to.
    /// </summary>
    /// <remarks>
    /// Tolerant of what actually arrives: display names, angle brackets,
    /// surrounding whitespace, and mixed case. Receivers echo the rua address
    /// back in various shapes and a strict match would drop real reports.
    ///
    /// Not tolerant of the domain, which must match the configured reporting
    /// domain exactly. Accepting a token from any domain would let an
    /// attacker who learned a token replay it from their own infrastructure.
    /// </remarks>
    public static bool TryParse(string? address, string reportingDomain, out string token)
    {
        token = "";
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(reportingDomain))
        {
            return false;
        }

        var cleaned = address.Trim();

        // "DMARC Reports <abc@rua.example.com>" -> the part in brackets.
        var open = cleaned.LastIndexOf('<');
        var close = cleaned.LastIndexOf('>');
        if (open >= 0 && close > open)
        {
            cleaned = cleaned[(open + 1)..close].Trim();
        }

        var at = cleaned.LastIndexOf('@');
        if (at <= 0 || at == cleaned.Length - 1) { return false; }

        var local = cleaned[..at].Trim().ToLowerInvariant();
        var domain = cleaned[(at + 1)..].Trim().TrimEnd('.').ToLowerInvariant();

        var expected = reportingDomain.Trim().TrimEnd('.').ToLowerInvariant();
        if (!string.Equals(domain, expected, StringComparison.Ordinal)) { return false; }

        // Some receivers append a +tag. Take what precedes it.
        var plus = local.IndexOf('+', StringComparison.Ordinal);
        if (plus > 0) { local = local[..plus]; }

        if (!IsValidToken(local)) { return false; }

        token = local;
        return true;
    }
}

/// <summary>How a report was attributed to a domain, and whether to trust it.</summary>
public enum AttributionOutcome
{
    /// <summary>The address and the report agree. Safe to ingest.</summary>
    Attributed,

    /// <summary>
    /// The address is not one we issued. Either a stale address from before a
    /// customer was removed, or unsolicited mail to the reporting domain.
    /// </summary>
    UnknownAddress,

    /// <summary>
    /// The address is ours but the report claims a different domain. This is
    /// the case worth alarming on: it is what an injected report looks like.
    /// </summary>
    DomainMismatch,

    /// <summary>
    /// Delivered to the shared fallback address rather than a per-domain one.
    /// Attribution rests on the report's own contents, which is weaker.
    /// </summary>
    FallbackAddress,
}

public sealed record AttributionResult
{
    public required AttributionOutcome Outcome { get; init; }

    /// <summary>The domain this report should be filed under, when trusted.</summary>
    public string Domain { get; init; } = "";

    public string Token { get; init; } = "";

    /// <summary>Plain-English reason, safe to show an operator or write to a log.</summary>
    public string Reason { get; init; } = "";

    /// <summary>Whether the report should be stored against a customer.</summary>
    public bool ShouldIngest => Outcome is AttributionOutcome.Attributed or AttributionOutcome.FallbackAddress;

    /// <summary>Whether somebody should look at this rather than it being filed quietly.</summary>
    public bool IsSuspicious => Outcome == AttributionOutcome.DomainMismatch;
}

/// <summary>
/// Decides which domain an arriving report belongs to, by requiring the
/// delivery address and the report's own contents to agree.
/// </summary>
public static class ReportAttribution
{
    /// <summary>
    /// Attributes a report.
    /// </summary>
    /// <param name="deliveredTo">The address the report was delivered to.</param>
    /// <param name="reportDomain">policy_published/domain from the report itself.</param>
    /// <param name="reportingDomain">The subdomain report addresses are issued under.</param>
    /// <param name="resolveToken">Maps an issued token to the domain it was issued for; null when unknown.</param>
    /// <param name="fallbackAddress">
    /// Optional shared address, for a deployment that has not moved to
    /// per-domain addressing yet. Reports here are ingested on the strength of
    /// their own contents, which is weaker and is reported as such rather than
    /// being silently treated as equivalent.
    /// </param>
    public static AttributionResult Attribute(
        string? deliveredTo,
        string reportDomain,
        string reportingDomain,
        Func<string, string?> resolveToken,
        string? fallbackAddress = null)
    {
        ArgumentNullException.ThrowIfNull(resolveToken);

        var claimed = (reportDomain ?? "").Trim().TrimEnd('.').ToLowerInvariant();

        if (ReportAddress.TryParse(deliveredTo, reportingDomain, out var token))
        {
            var issuedFor = resolveToken(token);

            if (string.IsNullOrWhiteSpace(issuedFor))
            {
                return new AttributionResult
                {
                    Outcome = AttributionOutcome.UnknownAddress,
                    Token = token,
                    Reason = "The report was delivered to an address that is not currently issued to any domain. "
                           + "This is expected for a short while after a domain is removed, because receivers keep "
                           + "sending to a published address until the record is changed.",
                };
            }

            var expected = issuedFor.Trim().TrimEnd('.').ToLowerInvariant();

            // Relaxed on purpose: a report for a subdomain legitimately
            // arrives at the parent's address, because that is where the
            // parent's DMARC record points.
            if (DomainsAgree(claimed, expected))
            {
                return new AttributionResult
                {
                    Outcome = AttributionOutcome.Attributed,
                    Domain = expected,
                    Token = token,
                    Reason = "The delivery address and the report agree on the domain.",
                };
            }

            return new AttributionResult
            {
                Outcome = AttributionOutcome.DomainMismatch,
                Domain = expected,
                Token = token,
                Reason = $"The report was delivered to the address issued for {expected} but claims to be about "
                       + $"{(string.IsNullOrEmpty(claimed) ? "no domain at all" : claimed)}. A genuine receiver does "
                       + "not do this. Treat it as an attempt to file fabricated data against a monitored domain.",
            };
        }

        if (!string.IsNullOrWhiteSpace(fallbackAddress) &&
            AddressMatches(deliveredTo, fallbackAddress))
        {
            return new AttributionResult
            {
                Outcome = AttributionOutcome.FallbackAddress,
                Domain = claimed,
                Reason = "Delivered to the shared reporting address, so the domain is taken from the report itself. "
                       + "Issue this domain its own address to make attribution verifiable.",
            };
        }

        return new AttributionResult
        {
            Outcome = AttributionOutcome.UnknownAddress,
            Reason = "The report was not delivered to a recognised reporting address.",
        };
    }

    /// <summary>
    /// Whether a report's domain belongs to the domain an address was issued
    /// for. Exact, or a subdomain of it.
    /// </summary>
    private static bool DomainsAgree(string claimed, string issuedFor)
    {
        if (string.IsNullOrEmpty(claimed) || string.IsNullOrEmpty(issuedFor)) { return false; }
        if (string.Equals(claimed, issuedFor, StringComparison.Ordinal)) { return true; }

        // Only downward: mail.acme.com is covered by acme.com's record, but
        // acme.com is NOT covered by an address issued for mail.acme.com.
        return claimed.EndsWith('.' + issuedFor, StringComparison.Ordinal);
    }

    private static bool AddressMatches(string? actual, string expected)
    {
        if (string.IsNullOrWhiteSpace(actual)) { return false; }

        var cleaned = actual.Trim();
        var open = cleaned.LastIndexOf('<');
        var close = cleaned.LastIndexOf('>');
        if (open >= 0 && close > open) { cleaned = cleaned[(open + 1)..close].Trim(); }

        return string.Equals(cleaned, expected.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
