using System.IO.Compression;
using System.Text;

namespace DmarcMonitor.Core.Ingest;

/// <summary>What kind of report a file turned out to hold.</summary>
public enum ReportKind
{
    Unknown,

    /// <summary>DMARC aggregate report (XML).</summary>
    DmarcAggregate,

    /// <summary>SMTP TLS reporting (JSON).</summary>
    TlsRpt,
}

/// <summary>One report recovered from an email attachment.</summary>
public sealed record ExtractedReport
{
    public required string FileName { get; init; }
    public required ReportKind Kind { get; init; }
    public required string Content { get; init; }
}

/// <summary>
/// Turns an email attachment into report text.
///
/// Reports arrive gzipped, zipped, or occasionally bare, named by convention
/// rather than by rule, and sometimes with a content type that disagrees with
/// the extension. So the kind is decided by looking at what came out, not by
/// trusting the name.
///
/// Everything here treats the attachment as hostile, because it is: anyone on
/// the internet can send mail to a published rua address. Decompression is
/// bounded, entry count is bounded, and paths inside archives are never used
/// to write anything.
/// </summary>
public static class ReportAttachment
{
    /// <summary>
    /// Largest decompressed report accepted, per entry. A legitimate
    /// aggregate report from a large receiver runs to a few megabytes; the
    /// biggest real sample here is under 100 KB. This bound is what stops a
    /// few hundred compressed bytes expanding into gigabytes of memory.
    /// </summary>
    public const int MaxDecompressedBytes = 64 * 1024 * 1024;

    /// <summary>
    /// Most entries read from one archive. Reports contain exactly one.
    /// </summary>
    public const int MaxArchiveEntries = 32;

    /// <summary>
    /// Extracts every report contained in an attachment.
    /// </summary>
    /// <remarks>
    /// Returns an empty list rather than throwing for anything it cannot
    /// make sense of. A single malformed attachment must not stop a run
    /// working through a backlog of thousands.
    /// </remarks>
    public static IReadOnlyList<ExtractedReport> Extract(string fileName, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        fileName ??= "";

        if (content.Length == 0) { return []; }

        try
        {
            if (LooksLikeZip(content)) { return FromZip(fileName, content); }
            if (LooksLikeGzip(content)) { return FromGzip(fileName, content); }
            return FromPlain(fileName, content);
        }
        catch (InvalidDataException) { return []; }
        catch (NotSupportedException) { return []; }
        catch (IOException) { return []; }
    }

    // Magic numbers rather than the file extension: real attachments arrive
    // with extensions that disagree with their contents, and a .gz that is
    // really a zip would otherwise be discarded.
    private static bool LooksLikeZip(byte[] b) =>
        b.Length >= 4 && b[0] == 0x50 && b[1] == 0x4B && (b[2] == 0x03 || b[2] == 0x05 || b[2] == 0x07);

    private static bool LooksLikeGzip(byte[] b) =>
        b.Length >= 3 && b[0] == 0x1F && b[1] == 0x8B && b[2] == 0x08;

    private static List<ExtractedReport> FromZip(string fileName, byte[] content)
    {
        var results = new List<ExtractedReport>();
        using var ms = new MemoryStream(content, writable: false);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var seen = 0;
        foreach (var entry in zip.Entries)
        {
            if (++seen > MaxArchiveEntries) { break; }
            if (entry.Length == 0) { continue; }

            // entry.Length is what the archive CLAIMS. It is attacker
            // controlled, so it is used only to reject early; the real
            // bound is enforced while reading.
            if (entry.Length > MaxDecompressedBytes) { continue; }

            using var es = entry.Open();
            var text = ReadBounded(es);
            if (text is null) { continue; }

            // entry.Name, never entry.FullName: FullName can contain
            // traversal segments. Nothing here writes to disk, but the name
            // reaches logs and reports, so it is kept harmless.
            var inner = string.IsNullOrWhiteSpace(entry.Name) ? fileName : entry.Name;
            var kind = Classify(text);
            if (kind != ReportKind.Unknown)
            {
                results.Add(new ExtractedReport { FileName = inner, Kind = kind, Content = text });
            }
        }
        return results;
    }

    private static List<ExtractedReport> FromGzip(string fileName, byte[] content)
    {
        using var ms = new MemoryStream(content, writable: false);
        using var gz = new GZipStream(ms, CompressionMode.Decompress);

        var text = ReadBounded(gz);
        if (text is null) { return []; }

        var kind = Classify(text);
        if (kind == ReportKind.Unknown) { return []; }

        // Strip the .gz so the name reads as the report it contains.
        var inner = fileName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
            ? fileName[..^3]
            : fileName;

        return [new ExtractedReport { FileName = inner, Kind = kind, Content = text }];
    }

    private static List<ExtractedReport> FromPlain(string fileName, byte[] content)
    {
        if (content.Length > MaxDecompressedBytes) { return []; }

        var text = Decode(content);
        var kind = Classify(text);
        return kind == ReportKind.Unknown
            ? []
            : [new ExtractedReport { FileName = fileName, Kind = kind, Content = text }];
    }

    /// <summary>
    /// Reads a decompressed stream, stopping at the cap.
    /// </summary>
    /// <remarks>
    /// Returns null when the cap is hit rather than returning what fit. A
    /// truncated report parses into plausible-looking nonsense, and reporting
    /// nonsense to a customer is worse than reporting nothing.
    /// </remarks>
    private static string? ReadBounded(Stream stream)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > MaxDecompressedBytes) { return null; }
            buffer.Write(chunk, 0, read);
        }
        return Decode(buffer.ToArray());
    }

    /// <summary>
    /// Decodes bytes to text, honouring a byte-order mark when present.
    /// Reports declare UTF-8 and generally are, but a BOM left in place ends
    /// up as a stray character before the XML declaration, which makes an
    /// otherwise valid report unparseable.
    /// </summary>
    private static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Decides what a file is by its content, not its name.
    /// </summary>
    /// <remarks>
    /// Receivers name these by convention, and the conventions differ. One
    /// real sample is called "...json.gz" and another "...xml.gz" from the
    /// same domain on the same day, and a DMARC report has been seen with a
    /// .json extension. Looking at the first meaningful character is both
    /// simpler and more reliable.
    /// </remarks>
    public static ReportKind Classify(string content)
    {
        if (string.IsNullOrWhiteSpace(content)) { return ReportKind.Unknown; }

        var i = 0;
        while (i < content.Length && char.IsWhiteSpace(content[i])) { i++; }
        if (i >= content.Length) { return ReportKind.Unknown; }

        if (content[i] == '{')
        {
            // TLS reports are the only JSON that arrives this way, but check
            // for the field that defines one rather than assuming.
            return content.Contains("\"policies\"", StringComparison.Ordinal)
                ? ReportKind.TlsRpt
                : ReportKind.Unknown;
        }

        if (content[i] == '<')
        {
            return content.Contains("<feedback", StringComparison.OrdinalIgnoreCase)
                ? ReportKind.DmarcAggregate
                : ReportKind.Unknown;
        }

        return ReportKind.Unknown;
    }
}
