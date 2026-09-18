namespace DmarcMonitor.Core.Dns;

/// <summary>A published DMARC record, broken into the tags that matter.</summary>
public sealed record DmarcRecord
{
    public required string Raw { get; init; }

    /// <summary>Set when the text is not a DMARC record at all.</summary>
    public string? Error { get; init; }

    public bool IsValid => Error is null;

    /// <summary>The domain's own policy. Empty when the record omits it, which is itself invalid.</summary>
    public string Policy { get; init; } = "";

    /// <summary>
    /// The subdomain policy, or empty when absent.
    /// </summary>
    /// <remarks>
    /// Empty means subdomains inherit the domain's policy, which is usually
    /// what somebody wants. It is deliberately not defaulted to Policy here:
    /// "inherits" and "explicitly set to the same thing" look identical
    /// afterwards, and the first is the one that keeps following the domain
    /// when it advances.
    /// </remarks>
    public string SubdomainPolicy { get; init; } = "";

    public int Percent { get; init; } = 100;

    /// <summary>Where aggregate reports are sent. Empty means nobody sees anything.</summary>
    public string Rua { get; init; } = "";

    /// <summary>
    /// <c>adkim=s</c>: a DKIM signature must be for this exact domain.
    /// </summary>
    /// <remarks>
    /// Relaxed unless the record says <c>s</c>, which is RFC 7489's default.
    /// It decides whether a signature over a subdomain of this domain counts,
    /// so a domain can be rejecting its own correctly-signed mail on the
    /// strength of this one character.
    /// </remarks>
    public bool StrictDkim { get; init; }

    /// <summary><c>aspf=s</c>: the same, for the envelope domain.</summary>
    public bool StrictSpf { get; init; }

    /// <summary>
    /// What subdomains are actually treated as, following inheritance.
    /// </summary>
    public string EffectiveSubdomainPolicy =>
        SubdomainPolicy.Length > 0 ? SubdomainPolicy : Policy;

    public static DmarcRecord Parse(string? text)
    {
        var raw = (text ?? string.Empty).Trim();

        if (raw.Length == 0)
        {
            return new DmarcRecord { Raw = raw, Error = "empty" };
        }

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) { continue; }

            tags[part[..equals].Trim()] = part[(equals + 1)..].Trim();
        }

        // The version tag is required and must come first. A TXT record at
        // _dmarc that does not have it is somebody else's record, not a broken
        // DMARC one, and treating it as broken would have somebody edit it.
        if (!tags.TryGetValue("v", out var version) ||
            !version.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
        {
            return new DmarcRecord { Raw = raw, Error = "does not begin with v=DMARC1" };
        }

        return new DmarcRecord
        {
            Raw = raw,
            Policy = tags.GetValueOrDefault("p", ""),
            SubdomainPolicy = tags.GetValueOrDefault("sp", ""),
            Percent = int.TryParse(tags.GetValueOrDefault("pct"), out var pct) ? pct : 100,
            Rua = tags.GetValueOrDefault("rua", ""),
            StrictDkim = IsStrict(tags.GetValueOrDefault("adkim")),
            StrictSpf = IsStrict(tags.GetValueOrDefault("aspf")),
        };
    }

    private static bool IsStrict(string? tag) =>
        string.Equals(tag?.Trim(), "s", StringComparison.OrdinalIgnoreCase);
}
