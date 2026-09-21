using System.Globalization;
using System.Text;

namespace DmarcMonitor.Core.Dns;

/// <summary>One resource record read out of a zone file.</summary>
public sealed record ZoneRecord
{
    /// <summary>The owner name, fully qualified, lower-case, with no trailing dot.</summary>
    public required string Name { get; init; }

    /// <summary>TXT, CNAME, MX, NS... upper-case.</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The record data.
    /// </summary>
    /// <remarks>
    /// For TXT this is the strings joined with nothing between them, which is
    /// how a resolver reassembles a record DNS split at 255 characters. A DKIM
    /// key arrives in two pieces in every GoDaddy export there is, and joining
    /// them with a space would corrupt the base64 and produce a confident
    /// finding about a key that is fine.
    /// </remarks>
    public required string Value { get; init; }

    /// <summary>
    /// The host this record points at, qualified, for the types that point at
    /// one: CNAME, NS, MX, SRV, PTR, DNAME. Empty for everything else.
    /// </summary>
    public string Target { get; init; } = "";

    /// <summary>The line the record starts on, so a finding can say where to look.</summary>
    public required int Line { get; init; }

    public int? Ttl { get; init; }
}

/// <summary>A line the parser could not read, and why.</summary>
/// <param name="Line">1-based line number in the file as pasted.</param>
/// <param name="Text">The line itself, trimmed, so the operator can see it.</param>
/// <param name="Reason">What stopped it being read.</param>
/// <remarks>
/// Reported rather than dropped. A parser that silently skips what it does not
/// understand is how an audit says "nothing wrong with this zone" about a file
/// it read half of.
/// </remarks>
public sealed record ZoneProblem(int Line, string Text, string Reason);

/// <summary>What a zone file turned out to contain.</summary>
public sealed record ParsedZone
{
    /// <summary>
    /// The domain the file is a zone for, lower-case and without a trailing
    /// dot. Empty when the file never said and nobody supplied one.
    /// </summary>
    public required string Origin { get; init; }

    /// <summary>
    /// The domain the file itself names, empty when it names none.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="Origin"/> so a caller can tell whether the
    /// origin came from the file or from itself. The two disagreeing is not a
    /// detail: it means the wrong file has been pasted, and a parser that
    /// quietly used the caller's answer would place every name in the file
    /// under a domain it has nothing to do with and audit it against another
    /// domain's reports.
    /// </remarks>
    public string DeclaredOrigin { get; init; } = "";

    public IReadOnlyList<ZoneRecord> Records { get; init; } = [];

    public IReadOnlyList<ZoneProblem> Problems { get; init; } = [];

    /// <summary>Every record of a type at one name.</summary>
    public IEnumerable<ZoneRecord> At(string name, string type) =>
        Records.Where(r => r.Type.Equals(type, StringComparison.OrdinalIgnoreCase)
                        && r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Reads a BIND-format zone export.
///
/// GoDaddy, Cloudflare and Route 53 all export this, and an operator who wants
/// a zone audited has the file in their hand already. It is the one input that
/// can enumerate what DNS cannot be asked to list - every DKIM selector, every
/// record left behind by a service that was retired years ago - because the
/// protocol offers no way to walk a zone and the authoritative server will not
/// transfer it to a stranger.
///
/// Parsing only. Nothing here judges anything: see <see cref="ZoneAudit"/>.
/// Keeping them apart is what lets every rule be tested against every shape of
/// file without a resolver, and keeps the two formats' differences - absolute
/// names against relative ones, one comment marker against two - in the one
/// place they belong.
/// </summary>
public static class ZoneFile
{
    private readonly record struct Token(string Text, bool Quoted);

    /// <summary>Classes a record can carry between its TTL and its type.</summary>
    private static readonly string[] Classes = ["IN", "CS", "CH", "HS"];

    /// <summary>
    /// Reads a zone file.
    /// </summary>
    /// <param name="text">The file, as pasted or as read from disk.</param>
    /// <param name="assumeOrigin">
    /// The domain to treat as the apex when the file does not say - a
    /// Cloudflare export carries no <c>$ORIGIN</c> directive at all, and a
    /// file pasted without its header says nothing either. It does not
    /// override a file that names itself: see
    /// <see cref="ParsedZone.DeclaredOrigin"/>.
    /// </param>
    public static ParsedZone Parse(string? text, string? assumeOrigin = null)
    {
        var lines = (text ?? string.Empty).ReplaceLineEndings("\n").Split('\n');

        var declared = FindOrigin(lines);
        var origin = declared ?? Normalize(assumeOrigin) ?? string.Empty;

        // Cloudflare writes every name in full and GoDaddy writes them all
        // relative to $ORIGIN. Which of the two this file is decides what a
        // name without a trailing dot means, and getting it wrong turns every
        // record in the file into a name under itself.
        var absolute = UsesAbsoluteNames(lines);

        // Whether a leading space means what BIND says it means.
        var indented = IndentCarriesMeaning(lines);

        var records = new List<ZoneRecord>();
        var problems = new List<ZoneProblem>();

        var current = origin;
        int? defaultTtl = null;
        string? lastName = null;

        var i = 0;
        while (i < lines.Length)
        {
            var start = i;

            // A record whose line begins with whitespace has no owner name of
            // its own and belongs to whichever name came before it. This is
            // ordinary in a hand-written zone and has to be read before the
            // line is tokenized, because tokenizing throws the spacing away.
            //
            // Unless the whole file is indented, in which case it is not
            // saying that at all - see IndentCarriesMeaning.
            var inherits = indented && lines[i].Length > 0 && char.IsWhiteSpace(lines[i][0]);

            var tokens = new List<Token>();
            var depth = 0;
            var unterminated = false;

            // Parentheses let one record span lines - every SOA does. The
            // depth has to be counted with the quoting in mind, or a bracket
            // inside a TXT string swallows the rest of the file.
            do
            {
                if (!Tokenize(lines[i], tokens, ref depth)) { unterminated = true; }
                i++;
            }
            while (!unterminated && depth > 0 && i < lines.Length);

            if (unterminated)
            {
                problems.Add(new ZoneProblem(start + 1, lines[start].Trim(), "a quoted string is not closed"));
                continue;
            }

            if (depth > 0)
            {
                problems.Add(new ZoneProblem(start + 1, lines[start].Trim(), "a bracket is never closed"));
                continue;
            }

            if (tokens.Count == 0) { continue; }

            if (tokens[0].Text.StartsWith('$') && !tokens[0].Quoted)
            {
                switch (tokens[0].Text.ToUpperInvariant())
                {
                    case "$ORIGIN" when tokens.Count > 1:
                        current = Qualify(tokens[1].Text, current, absolute);
                        break;

                    case "$TTL" when tokens.Count > 1:
                        defaultTtl = Ttl(tokens[1].Text);
                        break;

                    default:
                        // $INCLUDE names another file this has never seen, and
                        // $GENERATE expands into records this does not build.
                        // Either way the zone is bigger than what was read,
                        // and an audit that did not say so would be judging a
                        // fragment as if it were the whole thing.
                        problems.Add(new ZoneProblem(
                            start + 1, lines[start].Trim(),
                            $"{tokens[0].Text} is not followed, so part of this zone was not read"));
                        break;
                }

                continue;
            }

            var at = 0;
            string name;

            if (inherits)
            {
                if (lastName is null)
                {
                    problems.Add(new ZoneProblem(
                        start + 1, lines[start].Trim(),
                        "the record has no owner name and there is no earlier record to take one from"));
                    continue;
                }

                name = lastName;
            }
            else
            {
                name = Qualify(tokens[0].Text, current, absolute);
                at = 1;
            }

            // TTL and class may appear in either order, and either may be
            // absent. Both are consumed before the type, whatever order they
            // arrived in.
            var ttl = defaultTtl;
            for (var guard = 0; guard < 2 && at < tokens.Count; guard++)
            {
                if (Ttl(tokens[at].Text) is { } parsed) { ttl = parsed; at++; continue; }
                if (Classes.Contains(tokens[at].Text, StringComparer.OrdinalIgnoreCase)) { at++; continue; }
                break;
            }

            if (at >= tokens.Count)
            {
                problems.Add(new ZoneProblem(start + 1, lines[start].Trim(), "no record type"));
                continue;
            }

            var type = tokens[at].Text.ToUpperInvariant();
            at++;

            if (!LooksLikeAType(type))
            {
                problems.Add(new ZoneProblem(
                    start + 1, lines[start].Trim(), $"'{tokens[at - 1].Text}' is not a record type"));
                continue;
            }

            var rdata = tokens.GetRange(at, tokens.Count - at);

            records.Add(new ZoneRecord
            {
                Name = name,
                Type = type,
                Value = Rdata(type, rdata),
                Target = Target(type, rdata, current, absolute),
                Ttl = ttl,
                Line = start + 1,
            });

            lastName = name;
        }

        return new ParsedZone
        {
            Origin = origin,
            DeclaredOrigin = declared ?? string.Empty,
            Records = records,
            Problems = problems,
        };
    }

    /// <summary>
    /// Splits one line into tokens, dropping the comment and the brackets.
    /// </summary>
    /// <returns>False when a quoted string was left open at the end of the line.</returns>
    private static bool Tokenize(string line, List<Token> into, ref int depth)
    {
        var at = 0;

        while (at < line.Length)
        {
            var c = line[at];

            if (char.IsWhiteSpace(c)) { at++; continue; }

            // Only outside a quoted string. A semicolon inside one is data -
            // every DMARC and DKIM record in existence is full of them.
            if (c == ';') { return true; }

            if (c == '(') { depth++; at++; continue; }
            if (c == ')') { depth = Math.Max(0, depth - 1); at++; continue; }

            if (c == '"')
            {
                at++;
                var text = new StringBuilder();
                var closed = false;

                while (at < line.Length)
                {
                    if (line[at] == '\\' && at + 1 < line.Length)
                    {
                        text.Append(line[at + 1]);
                        at += 2;
                        continue;
                    }

                    if (line[at] == '"') { closed = true; at++; break; }

                    text.Append(line[at]);
                    at++;
                }

                if (!closed) { return false; }

                into.Add(new Token(text.ToString(), true));
                continue;
            }

            var word = at;
            while (at < line.Length && !char.IsWhiteSpace(line[at])
                   && line[at] is not (';' or '(' or ')' or '"'))
            {
                at++;
            }

            into.Add(new Token(line[word..at], false));
        }

        return true;
    }

    /// <summary>
    /// The record data, put back together the way a resolver would hand it over.
    /// </summary>
    private static string Rdata(string type, List<Token> rdata)
    {
        if (rdata.Count == 0) { return string.Empty; }

        // A TXT record longer than 255 characters is published as several
        // strings and read as one with nothing between them.
        if (type == "TXT" && rdata.TrueForAll(t => t.Quoted))
        {
            return string.Concat(rdata.Select(t => t.Text));
        }

        return string.Join(' ', rdata.Select(t => t.Text));
    }

    /// <summary>The host a record points at, for the types that point at one.</summary>
    private static string Target(string type, List<Token> rdata, string origin, bool absolute) => type switch
    {
        "CNAME" or "NS" or "PTR" or "DNAME" when rdata.Count >= 1 => Qualify(rdata[0].Text, origin, absolute),
        "MX" when rdata.Count >= 2 => Qualify(rdata[1].Text, origin, absolute),
        "SRV" when rdata.Count >= 4 => Qualify(rdata[3].Text, origin, absolute),
        _ => string.Empty,
    };

    /// <summary>
    /// Turns a name as written into the name it stands for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>.@</c> ending is GoDaddy's: it writes <c>_sip._tls.@</c> for a
    /// name under the origin, which no other exporter does and which reads as
    /// a label called "@" if taken literally.
    /// </para>
    /// <para>
    /// The check against the origin only applies to a file that writes its
    /// names in full, and that restriction is deliberate. In a file that
    /// writes them relative to <c>$ORIGIN</c>, a name that already ends in the
    /// domain is the classic control-panel slip - <c>mail.example.com</c>
    /// typed into a field that appends <c>.example.com</c> - and treating it
    /// as already qualified would hide exactly the defect somebody is running
    /// this to find.
    /// </para>
    /// </remarks>
    private static string Qualify(string name, string origin, bool absolute)
    {
        var text = name.Trim();

        if (text.Length == 0 || text == "@") { return origin; }
        if (text.EndsWith('.')) { return text.TrimEnd('.').ToLowerInvariant(); }
        if (text.EndsWith(".@", StringComparison.Ordinal)) { text = text[..^2]; }

        var lower = text.ToLowerInvariant();

        if (origin.Length == 0) { return lower; }

        if (absolute && (lower == origin || lower.EndsWith('.' + origin, StringComparison.Ordinal)))
        {
            return lower;
        }

        return lower + '.' + origin;
    }

    /// <summary>
    /// Which domain this file is a zone for, from the file itself.
    /// </summary>
    /// <remarks>
    /// Three sources, in the order they can be trusted: the directive that
    /// states it, the header comment every exporter writes, and the owner name
    /// of the SOA record, which is the apex by definition.
    /// </remarks>
    private static string? FindOrigin(string[] lines)
    {
        string? fromComment = null;
        string? fromSoa = null;

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();

            if (trimmed.StartsWith("$ORIGIN", StringComparison.OrdinalIgnoreCase))
            {
                var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1) { return Normalize(parts[1]); }
                continue;
            }

            if (trimmed.StartsWith(';'))
            {
                var header = trimmed.TrimStart(';').TrimStart();
                if (fromComment is null && header.StartsWith("Domain:", StringComparison.OrdinalIgnoreCase))
                {
                    fromComment = Normalize(header["Domain:".Length..]);
                }

                continue;
            }

            if (fromSoa is null && line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1 && Array.Exists(parts, p => p.Equals("SOA", StringComparison.OrdinalIgnoreCase)))
                {
                    fromSoa = Normalize(parts[0]);
                }
            }
        }

        return fromComment ?? fromSoa;
    }

    /// <summary>
    /// True when the file writes owner names in full rather than relative to
    /// an origin.
    /// </summary>
    private static bool UsesAbsoluteNames(string[] lines)
    {
        var any = false;

        foreach (var line in lines)
        {
            if (line.TrimStart().StartsWith("$ORIGIN", StringComparison.OrdinalIgnoreCase)) { return false; }

            if (any || line.Length == 0 || char.IsWhiteSpace(line[0]) || line.TrimStart().StartsWith(';'))
            {
                continue;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 0 && parts[0].EndsWith('.')) { any = true; }
        }

        return any;
    }

    /// <summary>
    /// Whether a leading space in this file means what BIND says it means.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In a zone file a line that starts with whitespace has no owner name and
    /// belongs to whichever name came before it. That is real and this parser
    /// honours it - a multi-line SOA and a second record for the same name
    /// both rely on it.
    /// </para>
    /// <para>
    /// But this also reads text somebody pasted into a box, and text copied
    /// out of a document, a ticket or a chat arrives uniformly indented. Taken
    /// literally, every line then inherits from the line above and the first
    /// one has nothing to inherit from, so the whole file yields no records at
    /// all and a page full of "no owner name". What the operator sees is a
    /// tool that cannot read their zone.
    /// </para>
    /// <para>
    /// The distinction is whether ANY record line is flush against the margin.
    /// If one is, indentation is carrying meaning and is honoured. If none is,
    /// it cannot be - there is no line for the first record to inherit from -
    /// so it is a paste artifact and is ignored.
    /// </para>
    /// </remarks>
    private static bool IndentCarriesMeaning(string[] lines)
    {
        foreach (var line in lines)
        {
            if (line.Length == 0 || char.IsWhiteSpace(line[0])) { continue; }

            var trimmed = line.TrimStart();
            if (trimmed.Length == 0 || trimmed.StartsWith(';')) { continue; }

            // A flush line that is not a comment. Somewhere in this file a
            // record starts at the margin, so an indented one beside it is
            // making the statement BIND says it is.
            return true;
        }

        return false;
    }

    /// <summary>
    /// A TTL, in seconds, or null when the token is not one.
    /// </summary>
    /// <remarks>
    /// BIND allows units and allows them to be run together, so "1h30m" is a
    /// TTL and so is "3600". Anything else is the class or the type, and
    /// reading it as a TTL would consume the record's type and leave the line
    /// unreadable.
    /// </remarks>
    internal static int? Ttl(string token)
    {
        if (token.Length == 0) { return null; }

        if (int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var plain))
        {
            return plain;
        }

        long total = 0;
        long number = 0;
        var digits = false;

        foreach (var c in token)
        {
            if (char.IsAsciiDigit(c))
            {
                number = (number * 10) + (c - '0');
                digits = true;

                // A zone file with a TTL this large is not a zone file.
                if (number > int.MaxValue) { return null; }
                continue;
            }

            if (!digits) { return null; }

            var seconds = char.ToLowerInvariant(c) switch
            {
                's' => 1L,
                'm' => 60L,
                'h' => 3600L,
                'd' => 86400L,
                'w' => 604800L,
                _ => 0L,
            };

            if (seconds == 0) { return null; }

            total += number * seconds;
            number = 0;
            digits = false;
        }

        // A trailing run of digits with no unit, after units were used, is not
        // something BIND accepts.
        if (digits) { return null; }

        return total is >= 0 and <= int.MaxValue ? (int)total : null;
    }

    private static bool LooksLikeAType(string token) =>
        token.Length > 0 && char.IsAsciiLetter(token[0])
        && token.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    private static string? Normalize(string? domain)
    {
        var text = domain?.Trim().TrimEnd('.').Trim();
        return string.IsNullOrEmpty(text) ? null : text.ToLowerInvariant();
    }
}
