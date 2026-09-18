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

/// <summary>
/// How much one file is allowed to decompress to, and whether it ran out.
/// </summary>
/// <remarks>
/// Two limits, because either alone bounds nothing useful. A byte cap with no
/// entry cap admits an archive of a million empty-ish members; an entry cap
/// with no byte cap admits thirty-two members of a gigabyte each.
///
/// The caller keeps the budget and reads <see cref="Exhausted"/> afterwards.
/// Extraction that quietly stops half way through somebody's export and
/// reports success is the failure this exists to prevent.
/// </remarks>
public sealed class ExtractionBudget
{
    public ExtractionBudget(int entries, long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(entries);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytes);

        EntriesRemaining = entries;
        BytesRemaining = bytes;
    }

    /// <summary>
    /// For a file that arrived by email, which is to say from anyone on the
    /// internet who found a published rua address.
    /// </summary>
    public static ExtractionBudget ForMail() =>
        new(ReportAttachment.MaxArchiveEntries, ReportAttachment.MaxTotalBytes);

    /// <summary>
    /// For a file an operator signed in and chose: a mailbox export really
    /// does hold thousands of reports. Larger than the mail budget, and still
    /// a budget, because a trusted operator can drop a zip bomb by accident
    /// as easily as a stranger can on purpose.
    /// </summary>
    public static ExtractionBudget ForOperator() =>
        new(ReportAttachment.MaxOperatorArchiveEntries, ReportAttachment.MaxOperatorTotalBytes);

    public int EntriesRemaining { get; private set; }

    public long BytesRemaining { get; private set; }

    /// <summary>Set once a read was refused, so there may be more that was not read.</summary>
    public bool Exhausted { get; private set; }

    /// <summary>
    /// Claims one archive member, or refuses when there are none left.
    /// </summary>
    /// <remarks>
    /// Charged where members are enumerated, not per decompression. A report
    /// inside an export is gzipped inside a zip, so it is decompressed twice
    /// on the way out, and charging it twice would halve every limit for the
    /// commonest shape there is.
    /// </remarks>
    internal bool TryTakeEntry()
    {
        if (EntriesRemaining <= 0)
        {
            Exhausted = true;
            return false;
        }

        EntriesRemaining--;
        return true;
    }

    /// <summary>Claims room for bytes about to be held, or refuses.</summary>
    internal bool TryTakeBytes(long length)
    {
        if (length > BytesRemaining)
        {
            Exhausted = true;
            return false;
        }

        BytesRemaining -= length;
        return true;
    }
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
    /// Most entries read from one archive on the mail path. A report arrives
    /// as one file, so an attachment holding dozens is already odd.
    /// </summary>
    public const int MaxArchiveEntries = 32;

    /// <summary>
    /// Everything one attachment may decompress to in total, across nesting.
    /// </summary>
    /// <remarks>
    /// Separate from the per-entry cap because the per-entry cap alone bounds
    /// nothing: an archive of a thousand entries, each just under the limit,
    /// is within it.
    /// </remarks>
    public const long MaxTotalBytes = 128L * 1024 * 1024;

    /// <summary>
    /// Archive entries read from a file an operator chose. Sized for a real
    /// mailbox export: the one this was built against holds 1,687.
    /// </summary>
    public const int MaxOperatorArchiveEntries = 25_000;

    /// <summary>Everything one operator-chosen file may decompress to.</summary>
    public const long MaxOperatorTotalBytes = 2L * 1024 * 1024 * 1024;

    /// <summary>
    /// How deep archives are followed.
    /// </summary>
    /// <remarks>
    /// A mailbox export is a zip of the attachments as they arrived, and
    /// those are themselves gzipped or zipped, so one level is the ordinary
    /// case rather than the exotic one. Three is enough for that with room
    /// to spare, and a bound is what stops an archive that contains itself.
    /// </remarks>
    public const int MaxArchiveDepth = 3;

    /// <summary>
    /// Extracts every report contained in an email attachment.
    /// </summary>
    /// <remarks>
    /// Returns an empty list rather than throwing for anything it cannot
    /// make sense of. A single malformed attachment must not stop a run
    /// working through a backlog of thousands.
    /// </remarks>
    public static IReadOnlyList<ExtractedReport> Extract(string fileName, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return [.. ExtractAll(fileName, content, ExtractionBudget.ForMail())];
    }

    /// <summary>
    /// Extracts reports from a file, with the caller setting the bounds.
    /// </summary>
    /// <remarks>
    /// Lazy, and deliberately so: an operator drops an export of a thousand
    /// reports and the caller stores each one and lets it go, rather than the
    /// whole export sitting in memory at once.
    ///
    /// The bounds are a parameter because the two ways a file arrives here
    /// are not equally trustworthy. An email attachment comes from anyone on
    /// the internet who found a published rua address, and gets
    /// <see cref="MaxArchiveEntries"/>. A file an operator signed in and
    /// chose gets whatever the upload path allows, which is larger because
    /// the export it is meant for really does hold thousands. Larger, not
    /// unbounded: a signed-in operator can still drop a zip bomb by mistake.
    /// </remarks>
    /// <param name="budget">
    /// How much this file may consume. The caller keeps it and can ask
    /// afterwards whether it ran out, so truncation is reportable rather than
    /// silent.
    /// </param>
    public static IEnumerable<ExtractedReport> ExtractAll(
        string fileName, byte[] content, ExtractionBudget budget)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(budget);

        return content.Length == 0
            ? []
            : Walk(fileName ?? "", content, budget, depth: 0);
    }

    private static IEnumerable<ExtractedReport> Walk(string fileName, byte[] content, ExtractionBudget budget, int depth)
    {
        if (depth > MaxArchiveDepth) { yield break; }

        if (LooksLikeZip(content))
        {
            foreach (var report in FromZip(fileName, content, budget, depth)) { yield return report; }
            yield break;
        }

        if (LooksLikeGzip(content))
        {
            var expanded = Expand(content, budget);
            if (expanded is null) { yield break; }

            // Strip the .gz so the name reads as the report it contains.
            var inner = fileName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
                ? fileName[..^3]
                : fileName;

            // Back through the top: a .gz inside an export can hold a zip.
            foreach (var report in Walk(inner, expanded, budget, depth + 1)) { yield return report; }
            yield break;
        }

        if (content.Length > MaxDecompressedBytes) { yield break; }

        var text = Decode(content);
        var kind = Classify(text);
        if (kind != ReportKind.Unknown)
        {
            yield return new ExtractedReport { FileName = fileName, Kind = kind, Content = text };
        }
    }

    private static IEnumerable<ExtractedReport> FromZip(string fileName, byte[] content, ExtractionBudget budget, int depth)
    {
        var zip = TryOpen(content);
        if (zip is null) { yield break; }

        using (zip)
        {
            foreach (var entry in zip.Entries)
            {
                if (entry.Length == 0) { continue; }

                // entry.Length is what the archive CLAIMS. It is attacker
                // controlled, so it is used only to reject early; the real
                // bound is enforced while reading.
                if (entry.Length > MaxDecompressedBytes) { continue; }

                var expanded = Expand(entry, budget);
                if (expanded is null) { continue; }

                // Charged once the member turned out to be readable, so an
                // empty or corrupt one does not spend another's place.
                if (!budget.TryTakeEntry()) { yield break; }

                // entry.Name, never entry.FullName: FullName can contain
                // traversal segments. Nothing here writes to disk, but the name
                // reaches logs and reports, so it is kept harmless.
                var inner = string.IsNullOrWhiteSpace(entry.Name) ? fileName : entry.Name;

                // Recursed rather than classified here, because what comes out
                // of an export zip is usually another archive: the attachments
                // as the receivers sent them.
                foreach (var report in Walk(inner, expanded, budget, depth + 1)) { yield return report; }
            }
        }
    }

    /// <summary>Opens an archive, or returns null when it is not one this can read.</summary>
    private static ZipArchive? TryOpen(byte[] content)
    {
        try
        {
            return new ZipArchive(new MemoryStream(content, writable: false), ZipArchiveMode.Read);
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            return null;
        }
    }

    // Magic numbers rather than the file extension: real attachments arrive
    // with extensions that disagree with their contents, and a .gz that is
    // really a zip would otherwise be discarded.
    private static bool LooksLikeZip(byte[] b) =>
        b.Length >= 4 && b[0] == 0x50 && b[1] == 0x4B && (b[2] == 0x03 || b[2] == 0x05 || b[2] == 0x07);

    private static bool LooksLikeGzip(byte[] b) =>
        b.Length >= 3 && b[0] == 0x1F && b[1] == 0x8B && b[2] == 0x08;

    /// <summary>Decompresses one archive entry within the budget.</summary>
    private static byte[]? Expand(ZipArchiveEntry entry, ExtractionBudget budget)
    {
        try
        {
            using var stream = entry.Open();
            return ReadBounded(stream, budget);
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            return null;
        }
    }

    /// <summary>Decompresses a gzip member within the budget.</summary>
    private static byte[]? Expand(byte[] content, ExtractionBudget budget)
    {
        try
        {
            using var source = new MemoryStream(content, writable: false);
            using var gz = new GZipStream(source, CompressionMode.Decompress);
            return ReadBounded(gz, budget);
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads a decompressed stream, stopping at the cap.
    /// </summary>
    /// <remarks>
    /// Returns null when a cap is hit rather than returning what fit. A
    /// truncated report parses into plausible-looking nonsense, and reporting
    /// nonsense to a customer is worse than reporting nothing.
    ///
    /// The budget is charged as the bytes arrive, not from the length the
    /// archive declares, because that number is written by whoever built the
    /// archive and a zip bomb declares whatever gets it past the check.
    /// </remarks>
    private static byte[]? ReadBounded(Stream stream, ExtractionBudget budget)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;

        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > MaxDecompressedBytes) { return null; }
            buffer.Write(chunk, 0, read);
        }

        // Charged for what it really came to, not for the length the archive
        // declared: that number is written by whoever built the archive.
        return budget.TryTakeBytes(buffer.Length) ? buffer.ToArray() : null;
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
