using System.Globalization;
using System.Text;

namespace DmarcMonitor.Core.Dns;

/// <summary>What a sender does when it cannot match the server it reached.</summary>
public static class MtaStsMode
{
    /// <summary>Report it and deliver anyway. Where every domain starts.</summary>
    public const string Testing = "testing";

    /// <summary>Refuse to deliver. The point of the exercise, and the dangerous half.</summary>
    public const string Enforce = "enforce";

    /// <summary>Published but switched off, which is how a policy is retired safely.</summary>
    public const string None = "none";
}

/// <summary>
/// An MTA-STS policy file (RFC 8461 §3.2).
///
/// Two halves have to agree for MTA-STS to do anything: a TXT record at
/// _mta-sts.&lt;domain&gt; announcing an id, and this file served over HTTPS at
/// mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt with a certificate that
/// validates. The DNS half is what this product can publish. The file has to
/// be served by a web server, which is why the app serves it.
///
/// The dangerous field is <see cref="Mx"/> under <see cref="MtaStsMode.Enforce"/>.
/// A sender that reaches a host not listed here does not deliver the message
/// and does not fall back - it defers and eventually bounces. So the list is
/// built from the domain's live MX records rather than typed, and enforce is
/// something a domain is moved to after evidence, never where it starts.
/// </summary>
public sealed record MtaStsPolicy
{
    /// <summary>testing, enforce or none.</summary>
    public required string Mode { get; init; }

    /// <summary>
    /// Hosts a sender may deliver to. A leading "*." wildcard matches one
    /// label, which is what a provider like Microsoft 365 needs.
    /// </summary>
    public required IReadOnlyList<string> Mx { get; init; }

    /// <summary>
    /// How long a sender may cache this, in seconds.
    /// </summary>
    /// <remarks>
    /// A week is the usual choice and is what this uses. It is also the reason
    /// a mistake in enforce mode is not simply undone: senders that already
    /// cached the broken policy keep honouring it until it expires, whatever
    /// is published afterwards.
    /// </remarks>
    public int MaxAgeSeconds { get; init; } = 604800;

    public const int DefaultMaxAgeSeconds = 604800;

    /// <summary>
    /// The version of this policy, as it appears in the TXT record.
    /// </summary>
    /// <remarks>
    /// A sender re-fetches the file only when this changes, so it must change
    /// whenever the file does, and must not change when the file does not - a
    /// value that moved every time it was read would have every sender on the
    /// internet fetching the file constantly.
    /// </remarks>
    public required string Id { get; init; }

    /// <summary>A policy in testing mode for these mail servers.</summary>
    public static MtaStsPolicy ForTesting(IReadOnlyList<string> mx, DateTimeOffset now) =>
        new() { Mode = MtaStsMode.Testing, Mx = mx, Id = IdFor(now) };

    /// <summary>An id from a timestamp, which is the convention and sorts usefully.</summary>
    public static string IdFor(DateTimeOffset when) =>
        when.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);

    /// <summary>
    /// Whether an id is one a sender will accept.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1: one to thirty-two alphanumeric characters. Worth
    /// checking rather than assuming, because the id cannot be read back out
    /// of the policy file - it exists only in the TXT record - so any code
    /// path that builds a record without being given one produces
    /// "v=STSv1; id=", which every sender treats as no policy at all.
    /// </remarks>
    public static bool IsValidId(string? id) =>
        id is { Length: > 0 and <= 32 } && id.All(char.IsLetterOrDigit);

    /// <summary>The file, exactly as it must be served.</summary>
    /// <remarks>
    /// CRLF line endings, because RFC 8461 §3.2 says so. Plenty of parsers
    /// accept LF and the ones that do not fail in ways nobody can see.
    /// </remarks>
    public string ToFile()
    {
        var text = new StringBuilder();
        text.Append("version: STSv1\r\n");
        text.Append("mode: ").Append(Mode).Append("\r\n");

        foreach (var host in Mx)
        {
            text.Append("mx: ").Append(host).Append("\r\n");
        }

        text.Append("max_age: ").Append(MaxAgeSeconds.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        return text.ToString();
    }

    /// <summary>The TXT record that announces it.</summary>
    public string ToRecord() => $"v=STSv1; id={Id}";

    /// <summary>
    /// Reads a policy file, as fetched from somebody's web server.
    /// </summary>
    /// <remarks>
    /// Lenient about line endings and spacing because this parses what is
    /// actually being served, which may have been written by hand or by
    /// another tool. Strict about the version line, because a file that does
    /// not declare STSv1 is not a policy and must not be read as one.
    /// </remarks>
    public static MtaStsPolicy? ParseFile(string? text, string id = "")
    {
        if (string.IsNullOrWhiteSpace(text)) { return null; }

        string? mode = null;
        var mx = new List<string>();
        var maxAge = DefaultMaxAgeSeconds;
        var declared = false;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0) { continue; }

            var key = line[..colon].Trim().ToLowerInvariant();
            var value = line[(colon + 1)..].Trim();

            switch (key)
            {
                case "version":
                    declared = value.Equals("STSv1", StringComparison.OrdinalIgnoreCase);
                    break;
                case "mode":
                    mode = value.ToLowerInvariant();
                    break;
                case "mx" when value.Length > 0:
                    mx.Add(value.TrimEnd('.').ToLowerInvariant());
                    break;
                case "max_age" when int.TryParse(value, out var seconds):
                    maxAge = seconds;
                    break;
            }
        }

        if (!declared || mode is null) { return null; }

        return new MtaStsPolicy { Mode = mode, Mx = mx, MaxAgeSeconds = maxAge, Id = id };
    }

    /// <summary>
    /// Whether this policy would let a sender deliver to a host.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.1: a "*." pattern matches exactly one label, so
    /// *.example.com covers mail.example.com and not a.b.example.com.
    /// Implemented rather than approximated, because this is the test that
    /// decides whether enforce mode is safe to turn on.
    /// </remarks>
    public bool Covers(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) { return false; }

        var name = host.Trim().TrimEnd('.').ToLowerInvariant();

        foreach (var pattern in Mx)
        {
            if (!pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                if (string.Equals(pattern, name, StringComparison.Ordinal)) { return true; }
                continue;
            }

            var suffix = pattern[1..];                       // ".example.com"
            if (!name.EndsWith(suffix, StringComparison.Ordinal)) { continue; }

            // One label, not several: the part before the suffix must not
            // itself contain a dot.
            var label = name[..^suffix.Length];
            if (label.Length > 0 && !label.Contains('.', StringComparison.Ordinal)) { return true; }
        }

        return false;
    }

    /// <summary>
    /// Mail servers this policy does not cover, which are the ones that would
    /// stop receiving mail if it were enforced.
    /// </summary>
    public IReadOnlyList<string> Uncovered(IEnumerable<string> mailServers) =>
        [.. (mailServers ?? []).Where(host => !Covers(host))];
}
