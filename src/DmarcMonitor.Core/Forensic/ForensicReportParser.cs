using System.Globalization;
using System.Text;

namespace DmarcMonitor.Core.Forensic;

/// <summary>
/// Parses a DMARC failure report: RFC 6591 fields inside RFC 5965 feedback.
///
/// Not XML and not JSON, which is why this is the report type the product had
/// never read. A failure report is an email - a multipart/report carrying
/// three parts: something human readable, a <c>message/feedback-report</c>
/// holding the fields, and a copy of the message that failed. So the work here
/// is MIME and RFC 5322 headers rather than a document format, and the hazards
/// are different ones: folded header lines, repeated headers, comments in
/// parentheses in the middle of a value, and a reported message that may be
/// the entire original mail.
///
/// Two shapes are accepted, because both turn up. A whole message, which is
/// what arrives in the mailbox; and a bare feedback-report part, which is what
/// a mailbox export or a receiver's own archive often writes out.
///
/// The body of the reported message is dropped here and never reaches
/// storage. A receiver is allowed to attach the whole original mail, and
/// keeping a customer's correspondence on an MSP's server because somebody
/// published ruf= is not a thing to do by accident. Headers answer every
/// question this feature exists for.
/// </summary>
public static class ForensicReportParser
{
    /// <summary>
    /// How much of the reported message's header block is kept.
    /// </summary>
    /// <remarks>
    /// Generous for real mail - a heavily forwarded message with long
    /// Authentication-Results and Received chains runs to a few kilobytes -
    /// and bounded, because this arrives from anyone who found a published
    /// ruf address.
    /// </remarks>
    public const int MaxHeaderBytes = 16 * 1024;

    /// <summary>
    /// Most headers read from one part.
    /// </summary>
    /// <remarks>
    /// A real message has tens. The cap is for a file that is nothing but
    /// header lines, which costs nothing to send and would otherwise be
    /// parsed in full.
    /// </remarks>
    public const int MaxHeaders = 512;

    /// <summary>Most MIME parts walked in one message.</summary>
    public const int MaxParts = 64;

    private static readonly char[] Whitespace = [' ', '\t'];

    public static ForensicParseResult Parse(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return ForensicParseResult.Failed("The report was empty.");
        }

        var (feedback, reported) = Split(content);

        if (feedback is null)
        {
            return ForensicParseResult.Failed(
                "The file has no message/feedback-report part, so it is not a failure report.");
        }

        // auth-failure is what makes this a DMARC failure report. The same
        // envelope carries abuse reports - a person pressing "this is spam" at
        // a large provider - and those are a different thing entirely, arrive
        // at the same mailbox, and must not be filed as authentication
        // failures for a domain.
        var type = First(feedback, "Feedback-Type");
        if (type.Length > 0 && !type.Equals("auth-failure", StringComparison.OrdinalIgnoreCase))
        {
            return ForensicParseResult.Failed(
                $"This is a '{type}' feedback report, not a DMARC failure report. "
                + "Those are about a person reporting spam rather than about authentication.");
        }

        var headers = Headers(reported);

        var domain = First(feedback, "Reported-Domain");
        if (domain.Length == 0) { domain = DomainOf(First(headers, "From")); }
        if (domain.Length == 0) { domain = DomainOf(First(feedback, "Original-Mail-From")); }

        if (domain.Length == 0)
        {
            // Every one of these is filed against a domain, and guessing which
            // beats nothing only until the guess is wrong - at which point one
            // customer is looking at another customer's mail.
            return ForensicParseResult.Failed(
                "The report does not say which domain it is about: no Reported-Domain, and no From "
                + "address in the reported message.");
        }

        var results = Authentication(feedback, headers);

        return ForensicParseResult.Succeeded(new ForensicReport
        {
            Domain = domain,
            ArrivalDate = Date(First(feedback, "Arrival-Date")) ?? Date(First(headers, "Date")),
            SourceIp = First(feedback, "Source-IP"),
            ReturnPath = Address(First(feedback, "Original-Mail-From")),
            HeaderFrom = First(headers, "From"),
            Subject = First(headers, "Subject"),

            // The reported message's own id where there is one. RFC 5965 also
            // allows a Message-ID in the feedback part meaning the same thing,
            // which is the only copy when a receiver sends headers it has
            // trimmed.
            MessageId = Address(Prefer(First(headers, "Message-ID"), First(feedback, "Message-ID"))),

            DkimResult = results.Dkim,
            SpfResult = results.Spf,
            DkimDomain = results.DkimDomain,
            AuthFailureType = First(feedback, "Auth-Failure"),
            DeliveryResult = First(feedback, "Delivery-Result"),
            ReportedBy = First(feedback, "User-Agent"),
            ReportedHeaders = reported,
        });
    }

    /// <summary>
    /// Splits a report into the feedback part and the reported message's
    /// headers.
    /// </summary>
    /// <remarks>
    /// Returns the feedback part as parsed headers and the reported message as
    /// its raw header block - raw because it is evidence, and re-serialising
    /// somebody's headers from a dictionary would quietly change them.
    /// </remarks>
    private static (IReadOnlyDictionary<string, List<string>>? Feedback, string Reported) Split(string content)
    {
        var boundary = BoundaryOf(Headers(HeaderBlockOf(content)));

        if (boundary is null)
        {
            // No MIME structure: a bare feedback-report part, which is how a
            // mailbox export usually writes one out. Only accepted as one when
            // it really carries the fields - otherwise any text file with a
            // colon in it would parse as a failure report about nothing.
            var bare = Headers(HeaderBlockOf(content));
            return bare.ContainsKey("feedback-type") || bare.ContainsKey("reported-domain")
                ? (bare, "")
                : (null, "");
        }

        IReadOnlyDictionary<string, List<string>>? feedback = null;
        var reported = "";

        foreach (var part in Parts(content, boundary))
        {
            var block = HeaderBlockOf(part);
            var partHeaders = Headers(block);
            var contentType = First(partHeaders, "Content-Type");
            var body = BodyOf(part);

            if (contentType.Contains("message/feedback-report", StringComparison.OrdinalIgnoreCase))
            {
                feedback = Headers(HeaderBlockOf(body));
            }
            else if (contentType.Contains("message/rfc822", StringComparison.OrdinalIgnoreCase)
                  || contentType.Contains("text/rfc822-headers", StringComparison.OrdinalIgnoreCase))
            {
                // Header block only. message/rfc822 may legitimately carry the
                // entire original mail, and HeaderBlockOf stops at the blank
                // line that ends the headers - which is where the body, and
                // the decision not to keep it, begins.
                reported = Cap(HeaderBlockOf(body));
            }
        }

        // A multipart with no feedback part but a recognizable one nested
        // inside it, which some receivers produce by wrapping the whole report
        // once more. Worth one look rather than a recursive walk.
        if (feedback is null)
        {
            var whole = Headers(content);
            if (whole.ContainsKey("feedback-type")) { feedback = whole; }
        }

        return (feedback, reported);
    }

    /// <summary>The MIME parts between one boundary and the next.</summary>
    private static List<string> Parts(string content, string boundary)
    {
        var marker = "--" + boundary;
        var parts = new List<string>();

        var lines = content.Split('\n');
        var current = new StringBuilder();
        var inside = false;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');

            if (line.StartsWith(marker, StringComparison.Ordinal))
            {
                if (inside)
                {
                    parts.Add(current.ToString());
                    current.Clear();
                    if (parts.Count >= MaxParts) { break; }
                }

                inside = true;

                // The closing delimiter, "--boundary--", ends the multipart.
                if (line.Length > marker.Length && line.AsSpan(marker.Length).TrimEnd().StartsWith("--")) { break; }

                continue;
            }

            if (inside) { current.Append(line).Append('\n'); }
        }

        if (inside && current.Length > 0 && parts.Count < MaxParts) { parts.Add(current.ToString()); }

        return parts;
    }

    /// <summary>
    /// The header block: everything up to the first blank line.
    /// </summary>
    /// <remarks>
    /// This is the line that keeps somebody's mail out of the database. RFC
    /// 5322 separates headers from body with one empty line, so stopping here
    /// is both correct and the whole of the privacy decision.
    /// </remarks>
    private static string HeaderBlockOf(string text)
    {
        var lines = text.Split('\n');
        var block = new StringBuilder();

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) { break; }

            block.Append(line).Append('\n');
            if (block.Length > MaxHeaderBytes) { break; }
        }

        return block.ToString();
    }

    /// <summary>Everything after the first blank line.</summary>
    private static string BodyOf(string text)
    {
        var at = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (at >= 0) { return text[(at + 2)..]; }

        at = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return at >= 0 ? text[(at + 4)..] : "";
    }

    /// <summary>
    /// Header names to values, lower-cased names, folded lines joined.
    /// </summary>
    /// <remarks>
    /// A list per name rather than one value: Authentication-Results and
    /// Received both repeat legitimately, and keeping the first while
    /// discarding the rest loses the DKIM result on any message a receiver
    /// checked in two passes.
    /// </remarks>
    private static Dictionary<string, List<string>> Headers(string block)
    {
        var headers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        if (block.Length == 0) { return headers; }

        string? name = null;
        var value = new StringBuilder();

        void Flush()
        {
            if (name is null) { return; }
            if (!headers.TryGetValue(name, out var list)) { headers[name] = list = []; }
            list.Add(value.ToString().Trim());
            name = null;
            value.Clear();
        }

        foreach (var raw in block.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) { break; }

            // A line starting with space or tab continues the one before it.
            // Unfolding is what makes a long Authentication-Results readable
            // as one value rather than as a header and some orphaned text.
            if (line[0] is ' ' or '\t')
            {
                if (name is not null) { value.Append(' ').Append(line.Trim()); }
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0) { continue; }

            Flush();
            if (headers.Count >= MaxHeaders) { break; }

            name = line[..colon].Trim().ToLowerInvariant();
            value.Append(line[(colon + 1)..].Trim());
        }

        Flush();
        return headers;
    }

    private static string First(IReadOnlyDictionary<string, List<string>>? headers, string name) =>
        headers is not null && headers.TryGetValue(name.ToLowerInvariant(), out var values) && values.Count > 0
            ? values[0]
            : "";

    private static string Prefer(string first, string second) => first.Length > 0 ? first : second;

    /// <summary>The boundary= of a multipart Content-Type, or null when there is none.</summary>
    private static string? BoundaryOf(IReadOnlyDictionary<string, List<string>> headers)
    {
        var contentType = First(headers, "Content-Type");
        if (!contentType.Contains("multipart/", StringComparison.OrdinalIgnoreCase)) { return null; }

        var at = contentType.IndexOf("boundary=", StringComparison.OrdinalIgnoreCase);
        if (at < 0) { return null; }

        var rest = contentType[(at + "boundary=".Length)..].Trim();
        if (rest.StartsWith('"'))
        {
            var close = rest.IndexOf('"', 1);
            return close > 1 ? rest[1..close] : null;
        }

        var end = rest.IndexOfAny([';', ' ', '\t']);
        var boundary = end < 0 ? rest : rest[..end];
        return boundary.Length > 0 ? boundary : null;
    }

    /// <summary>
    /// What the receiver's checks said, from Authentication-Results.
    /// </summary>
    /// <remarks>
    /// Read from the feedback part where it is, and from the reported
    /// message's headers where it is not: receivers put it in one place or the
    /// other and RFC 6591 allows both.
    /// </remarks>
    private static (string Dkim, string Spf, string DkimDomain) Authentication(
        IReadOnlyDictionary<string, List<string>> feedback,
        IReadOnlyDictionary<string, List<string>> reported)
    {
        string dkim = "", spf = "", dkimDomain = "";

        foreach (var line in All(feedback, "Authentication-Results").Concat(All(reported, "Authentication-Results")))
        {
            foreach (var chunk in Uncommented(line).Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var tokens = chunk.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length == 0) { continue; }

                var (method, result) = Pair(tokens[0]);

                if (method.Equals("dkim", StringComparison.OrdinalIgnoreCase))
                {
                    if (dkim.Length == 0) { dkim = result; }

                    foreach (var token in tokens.Skip(1))
                    {
                        var (property, domain) = Pair(token);
                        if (property.Equals("header.d", StringComparison.OrdinalIgnoreCase) && dkimDomain.Length == 0)
                        {
                            dkimDomain = domain;
                        }
                    }
                }
                else if (method.Equals("spf", StringComparison.OrdinalIgnoreCase) && spf.Length == 0)
                {
                    spf = result;
                }
            }
        }

        return (dkim, spf, dkimDomain);
    }

    private static List<string> All(IReadOnlyDictionary<string, List<string>> headers, string name) =>
        headers.TryGetValue(name.ToLowerInvariant(), out var values) ? values : [];

    private static (string Name, string Value) Pair(string token)
    {
        var at = token.IndexOf('=', StringComparison.Ordinal);
        return at <= 0 ? ("", "") : (token[..at].Trim(), token[(at + 1)..].Trim().Trim('"'));
    }

    /// <summary>
    /// The value with RFC 5322 comments removed.
    /// </summary>
    /// <remarks>
    /// "dkim=fail (body hash did not verify) header.d=example.com" is ordinary
    /// and common, and splitting it on whitespace without this produces tokens
    /// like "(body" that match nothing and a header.d that is never found.
    /// Comments nest, so the depth is counted rather than the first bracket
    /// being matched with the first close.
    /// </remarks>
    private static string Uncommented(string value)
    {
        if (!value.Contains('(', StringComparison.Ordinal)) { return value; }

        var output = new StringBuilder(value.Length);
        var depth = 0;

        foreach (var c in value)
        {
            if (c == '(') { depth++; continue; }
            if (c == ')') { if (depth > 0) { depth--; } continue; }
            if (depth == 0) { output.Append(c); }
        }

        return output.ToString();
    }

    /// <summary>The domain of an address, or empty when there is not one.</summary>
    private static string DomainOf(string address)
    {
        var bare = Address(address);
        var at = bare.LastIndexOf('@');
        if (at < 0 || at == bare.Length - 1) { return ""; }

        return bare[(at + 1)..].Trim().TrimEnd('.').ToLowerInvariant();
    }

    /// <summary>
    /// The address out of a From-style value: angle brackets stripped, display
    /// name dropped.
    /// </summary>
    private static string Address(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0) { return ""; }

        var open = trimmed.LastIndexOf('<');
        var close = trimmed.LastIndexOf('>');

        if (open >= 0 && close > open) { return trimmed[(open + 1)..close].Trim(); }

        return trimmed;
    }

    /// <summary>
    /// An RFC 5322 date, or null.
    /// </summary>
    /// <remarks>
    /// Never throws and never guesses. A report whose Arrival-Date does not
    /// parse is still a report worth keeping, and inventing "now" for it would
    /// file a message from last month under today.
    /// </remarks>
    private static DateTimeOffset? Date(string value)
    {
        var text = value.Trim();
        if (text.Length == 0) { return null; }

        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
        {
            return parsed;
        }

        // "Mon, 1 Jan 2026 09:14:00 -0000 (UTC)" - the trailing comment is
        // legal and .NET will not take it.
        var comment = text.IndexOf('(', StringComparison.Ordinal);
        if (comment > 0)
        {
            text = text[..comment].Trim();
            if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
            {
                return parsed;
            }
        }

        // A day name that does not match the date. .NET rejects the whole
        // value over it, and the value is perfectly good: the date, the time
        // and the offset are unambiguous and the weekday is decoration that
        // the sender's own code got wrong.
        //
        // Not hypothetical - it was the first thing two hand-built sample
        // reports hit, and losing the timestamp is not a small loss here.
        // These are individual messages, so the arrival time is a real event
        // at a real minute, and without it every report in the list reads as
        // having happened at the moment it was imported.
        var comma = text.IndexOf(',', StringComparison.Ordinal);
        if (comma > 0 && comma <= 4
            && DateTimeOffset.TryParse(
                text[(comma + 1)..].Trim(), CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
        {
            return parsed;
        }

        return null;
    }

    private static string Cap(string text) =>
        text.Length <= MaxHeaderBytes ? text : text[..MaxHeaderBytes];
}
