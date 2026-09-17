namespace DmarcMonitor.Core.Dns;

/// <summary>One term in an SPF record, in the order it was written.</summary>
public sealed record SpfTerm
{
    /// <summary>"include", "a", "mx", "ip4", "all", "redirect"...</summary>
    public required string Name { get; init; }

    /// <summary>What followed the colon or equals, if anything.</summary>
    public string Value { get; init; } = "";

    /// <summary>+, -, ~ or ?. Mechanisms only; "+" when it was left implicit.</summary>
    public char Qualifier { get; init; } = '+';

    /// <summary>The term exactly as it appeared, for showing an operator their own record.</summary>
    public required string Raw { get; init; }

    /// <summary>
    /// Whether evaluating this term costs one of the ten DNS lookups.
    /// </summary>
    /// <remarks>
    /// RFC 7208 section 4.6.4 counts include, a, mx, ptr, exists and redirect.
    /// ip4 and ip6 are free, which is the whole reason flattening a record
    /// works. Getting this list wrong in either direction is the difference
    /// between telling somebody their record is fine and telling them it is
    /// about to stop working.
    /// </remarks>
    public bool CostsALookup =>
        Name is "include" or "a" or "mx" or "ptr" or "exists" or "redirect";
}

/// <summary>A parsed SPF record, or the reason it could not be one.</summary>
public sealed record SpfRecord
{
    public required string Raw { get; init; }
    public IReadOnlyList<SpfTerm> Terms { get; init; } = [];

    /// <summary>Set when the text is not a usable SPF record at all.</summary>
    public string? Error { get; init; }

    public bool IsValid => Error is null;

    /// <summary>
    /// DNS lookups this record costs before any nesting is followed.
    /// </summary>
    /// <remarks>
    /// A floor, not the real figure: each include pulls in another record that
    /// spends lookups of its own, and the limit applies to the whole
    /// evaluation. A record showing 9 here can still fail. Named Direct rather
    /// than Total so nothing reads it as the answer.
    /// </remarks>
    public int DirectLookups => Terms.Count(t => t.CostsALookup);

    /// <summary>The final "all" mechanism, which decides what happens to everything else.</summary>
    public SpfTerm? All => Terms.LastOrDefault(t => t.Name == "all");

    /// <summary>
    /// Parses an SPF record.
    /// </summary>
    /// <remarks>
    /// Deliberately lenient about spacing and case, because real records are
    /// hand-edited in provider control panels and arrive with double spaces
    /// and capitals. Strict about the version prefix, because a TXT record
    /// that does not begin with v=spf1 is not an SPF record and must not be
    /// treated as a broken one.
    /// </remarks>
    public static SpfRecord Parse(string? text)
    {
        var raw = (text ?? string.Empty).Trim();

        if (raw.Length == 0)
        {
            return new SpfRecord { Raw = raw, Error = "empty" };
        }

        var parts = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (!parts[0].Equals("v=spf1", StringComparison.OrdinalIgnoreCase))
        {
            return new SpfRecord { Raw = raw, Error = "does not begin with v=spf1" };
        }

        var terms = new List<SpfTerm>();

        foreach (var part in parts.Skip(1))
        {
            var qualifier = '+';
            var body = part;

            // Modifiers (redirect=, exp=) never carry a qualifier, and a
            // leading '+' on one would be part of the name rather than a
            // qualifier, so only strip it from mechanisms.
            if (!body.Contains('=', StringComparison.Ordinal) && body.Length > 0 && body[0] is '+' or '-' or '~' or '?')
            {
                qualifier = body[0];
                body = body[1..];
            }

            var separator = body.IndexOfAny([':', '=']);
            var name = (separator < 0 ? body : body[..separator]).ToLowerInvariant();
            var value = separator < 0 ? "" : body[(separator + 1)..];

            terms.Add(new SpfTerm { Name = name, Value = value, Qualifier = qualifier, Raw = part });
        }

        return new SpfRecord { Raw = raw, Terms = terms };
    }
}
