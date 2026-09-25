using System.Buffers.Binary;
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

    /// <summary>
    /// DMARC failure report (RFC 6591), which is an email rather than a
    /// document.
    /// </summary>
    /// <remarks>
    /// The one report type that is neither XML nor JSON, which is why it went
    /// unread for so long: a classifier that looks at the first meaningful
    /// character sees a header line and has nothing to say about it.
    /// </remarks>
    DmarcFailure,
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
    /// What could not be read, one line each: an archive that would not open,
    /// a member that would not decompress, a gzip file cut short.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kept here for the same reason as <see cref="Exhausted"/>: the caller has
    /// to be able to ask afterwards what was NOT read. A damaged archive used
    /// to come back as an empty list - the same answer a zip of holiday photos
    /// gets - so an import counted it as "not a report", and a damaged member
    /// inside an export disappeared without a word while the rest imported.
    /// </para>
    /// <para>
    /// Each line names the member it is about when the damage is inside the
    /// file, and nothing when it is the file itself, so the caller prefixes
    /// the file's own name.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Unreadable => _unreadable;

    private readonly List<string> _unreadable = [];

    internal void NoteUnreadable(string what) => _unreadable.Add(what);

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
    /// working through a backlog of thousands. A caller that needs to know
    /// what could not be read uses <see cref="ExtractAll"/> and asks the
    /// budget afterwards.
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
    /// afterwards whether it ran out, and what could not be read at all, so
    /// truncation and damage are reportable rather than silent.
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

    /// <summary>Said of anything bigger than one report can be.</summary>
    private static readonly string TooLarge =
        $"larger than the {MaxDecompressedBytes / (1024 * 1024)} MB a single report may be, so it was not read";

    private static IEnumerable<ExtractedReport> Walk(string fileName, byte[] content, ExtractionBudget budget, int depth)
    {
        if (depth > MaxArchiveDepth)
        {
            // Said rather than dropped. The bound is what stops an archive that
            // contains itself, but whatever sat below it went unread.
            Unreadable(budget, fileName, depth, $"nested inside more than {MaxArchiveDepth} archives, deeper than this reads");
            yield break;
        }

        if (LooksLikeZip(content))
        {
            foreach (var report in FromZip(fileName, content, budget, depth)) { yield return report; }
            yield break;
        }

        if (LooksLikeGzip(content))
        {
            var expanded = Expand(fileName, content, budget, depth);
            if (expanded is null) { yield break; }

            // Strip the .gz so the name reads as the report it contains.
            var inner = fileName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
                ? fileName[..^3]
                : fileName;

            // Back through the top: a .gz inside an export can hold a zip.
            foreach (var report in Walk(inner, expanded, budget, depth + 1)) { yield return report; }
            yield break;
        }

        if (content.Length > MaxDecompressedBytes)
        {
            Unreadable(budget, fileName, depth, TooLarge);
            yield break;
        }

        var text = Decode(content);
        var kind = Classify(text);
        if (kind != ReportKind.Unknown)
        {
            yield return new ExtractedReport { FileName = fileName, Kind = kind, Content = text };
        }
    }

    private static IEnumerable<ExtractedReport> FromZip(string fileName, byte[] content, ExtractionBudget budget, int depth)
    {
        var zip = TryOpen(content, out var entries, out var why);
        if (zip is null)
        {
            Unreadable(budget, fileName, depth, $"could not be opened as a zip archive ({why})");
            yield break;
        }

        using (zip)
        {
            foreach (var entry in entries)
            {
                if (entry.Length == 0) { continue; }

                // entry.Name, never entry.FullName: FullName can contain
                // traversal segments. Nothing here writes to disk, but the name
                // reaches logs and reports, so it is kept harmless.
                var inner = string.IsNullOrWhiteSpace(entry.Name) ? fileName : entry.Name;

                // entry.Length is what the archive CLAIMS. It is attacker
                // controlled, so it is used only to reject early; the real
                // bound is enforced while reading.
                if (entry.Length > MaxDecompressedBytes)
                {
                    Unreadable(budget, inner, depth + 1, TooLarge);
                    continue;
                }

                var expanded = Expand(entry, inner, budget, depth + 1);
                if (expanded is null) { continue; }

                // Charged once the member turned out to be readable, so an
                // empty or corrupt one does not spend another's place.
                if (!budget.TryTakeEntry()) { yield break; }

                // Recursed rather than classified here, because what comes out
                // of an export zip is usually another archive: the attachments
                // as the receivers sent them.
                foreach (var report in Walk(inner, expanded, budget, depth + 1)) { yield return report; }
            }
        }
    }

    /// <summary>
    /// Opens an archive and reads its list of contents, or says why it could not.
    /// </summary>
    /// <remarks>
    /// Both halves inside the one try. ZipArchive reads the archive's end
    /// record when it is constructed, but the list of what is in it only when
    /// <see cref="ZipArchive.Entries"/> is first touched - so an archive whose
    /// list was damaged opened cleanly and then threw from the loop over its
    /// entries, which sat outside any try. One such file ended a whole folder
    /// import instead of being skipped, and the files after it were never read.
    /// </remarks>
    private static ZipArchive? TryOpen(byte[] content, out IReadOnlyList<ZipArchiveEntry> entries, out string why)
    {
        ZipArchive? zip = null;
        try
        {
            zip = new ZipArchive(new MemoryStream(content, writable: false), ZipArchiveMode.Read);
            entries = [.. zip.Entries];
            why = "";
            return zip;
        }
        catch (Exception ex) when (IsDamage(ex))
        {
            zip?.Dispose();
            entries = [];
            why = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// Whether an exception from reading an archive means "this input is
    /// damaged", as opposed to something the process cannot carry on from.
    /// </summary>
    /// <remarks>
    /// Wider than the exception types the documentation lists, on purpose. The
    /// input is hostile, the documentation is not a promise about what a
    /// crafted archive can provoke from the reader, and any exception escaping
    /// from here ends an import of a thousand files over one of them.
    /// </remarks>
    private static bool IsDamage(Exception ex) => ex is not OutOfMemoryException;

    /// <summary>
    /// Records something that could not be read, named for the member it is
    /// about - or for nothing when it is the file the caller handed over,
    /// because the caller names that one itself.
    /// </summary>
    private static void Unreadable(ExtractionBudget budget, string name, int depth, string problem) =>
        budget.NoteUnreadable(depth == 0 || string.IsNullOrWhiteSpace(name) ? problem : $"{name}: {problem}");

    // Magic numbers rather than the file extension: real attachments arrive
    // with extensions that disagree with their contents, and a .gz that is
    // really a zip would otherwise be discarded.
    private static bool LooksLikeZip(byte[] b) =>
        b.Length >= 4 && b[0] == 0x50 && b[1] == 0x4B && (b[2] == 0x03 || b[2] == 0x05 || b[2] == 0x07);

    private static bool LooksLikeGzip(byte[] b) =>
        b.Length >= 3 && b[0] == 0x1F && b[1] == 0x8B && b[2] == 0x08;

    /// <summary>Decompresses one archive entry within the budget.</summary>
    private static byte[]? Expand(ZipArchiveEntry entry, string name, ExtractionBudget budget, int depth)
    {
        try
        {
            using var stream = entry.Open();
            return ReadBounded(stream, name, budget, depth);
        }
        catch (Exception ex) when (IsDamage(ex))
        {
            Unreadable(budget, name, depth, $"could not be decompressed ({ex.Message})");
            return null;
        }
    }

    /// <summary>Decompresses a gzip file within the budget.</summary>
    private static byte[]? Expand(string name, byte[] content, ExtractionBudget budget, int depth)
    {
        byte[]? expanded;
        try
        {
            using var source = new MemoryStream(content, writable: false);
            using var gz = new GZipStream(source, CompressionMode.Decompress);
            expanded = ReadBounded(gz, name, budget, depth);
        }
        catch (Exception ex) when (IsDamage(ex))
        {
            Unreadable(budget, name, depth, $"could not be decompressed ({ex.Message})");
            return null;
        }

        if (expanded is not null && !ReachedItsEnd(content, expanded.Length))
        {
            Unreadable(budget, name, depth,
                "cut short: it ends part way through its own compressed data, so what it holds is incomplete");
            return null;
        }

        return expanded;
    }

    /// <summary>The three bytes every gzip member begins with.</summary>
    private static ReadOnlySpan<byte> GzipMagic => [0x1F, 0x8B, 0x08];

    /// <summary>
    /// Whether a gzip file got as far as the end its own trailer describes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needed because GZipStream does not complain about a file that stops
    /// short: it hands back whatever it had decoded when the bytes ran out.
    /// Cut in half, a report came out as its first half and failed to parse
    /// as something it was not; cut early, it came out as nothing at all and
    /// was counted as "not a report"; and a failure report, which is plain
    /// text, would have been stored with half its headers.
    /// </para>
    /// <para>
    /// RFC 1952 ends a gzip file with the length of what went into it, so a
    /// whole file carries the length of what came out and one cut short does
    /// not. It is looked for anywhere after the header rather than only in
    /// the last four bytes, because a file with a newline or padding after it
    /// is whole and decompresses whole. A file of several gzip members joined
    /// together is legal too, decompresses to all of them, and carries only
    /// the last one's length - so a second gzip header means this cannot tell,
    /// and the file is read exactly as it always was rather than refused.
    /// </para>
    /// </remarks>
    private static bool ReachedItsEnd(byte[] gzip, int expandedLength)
    {
        Span<byte> declared = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(declared, (uint)expandedLength);

        // Past the fixed ten-byte header, which is no part of any trailer.
        var rest = gzip.AsSpan(Math.Min(10, gzip.Length));
        return rest.IndexOf(declared) >= 0 || rest.IndexOf(GzipMagic) >= 0;
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
    private static byte[]? ReadBounded(Stream stream, string name, ExtractionBudget budget, int depth)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;

        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > MaxDecompressedBytes)
            {
                Unreadable(budget, name, depth, TooLarge);
                return null;
            }
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
    /// <summary>
    /// How far into a file the failure-report markers are looked for.
    /// </summary>
    /// <remarks>
    /// A failure report announces itself in the top Content-Type, and its
    /// feedback part follows a short human-readable one - both comfortably
    /// inside this. The bound exists so classifying a large file that is not a
    /// report does not scan all of it twice.
    /// </remarks>
    internal const int FeedbackScanBytes = 32 * 1024;

    public static ReportKind Classify(string content)
    {
        if (string.IsNullOrWhiteSpace(content)) { return ReportKind.Unknown; }

        // Checked before the shape tests, because this one is an email: it
        // begins with a header line, which is neither '<' nor '{' and would
        // otherwise fall through to Unknown - exactly as it did until failure
        // reports were parsed at all.
        //
        // Both markers are needed. A whole message carries the report-type
        // parameter on its Content-Type; a bare feedback part, which is what a
        // mailbox export writes out, carries only the field.
        var head = content.Length <= FeedbackScanBytes ? content : content[..FeedbackScanBytes];
        if (head.Contains("report-type=feedback-report", StringComparison.OrdinalIgnoreCase)
            || head.Contains("message/feedback-report", StringComparison.OrdinalIgnoreCase)
            || head.Contains("Feedback-Type:", StringComparison.OrdinalIgnoreCase))
        {
            return ReportKind.DmarcFailure;
        }

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
