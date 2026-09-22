using System.Reflection;
using PdfSharp.Fonts;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// The fonts a PDF report is drawn with, compiled into the binary.
/// </summary>
/// <remarks>
/// <para>
/// PDFsharp resolves fonts through the host on Windows and has nothing to fall
/// back on anywhere else, so a report that renders on a laptop throws on the
/// Linux container that is supposed to produce it every month. The fix is not
/// to install fonts on the server - it is for the product to carry the two it
/// uses, exactly as it carries its own schema.
/// </para>
/// <para>
/// Liberation Sans, under the SIL Open Font License 1.1, whose text is
/// embedded beside it and is printed by <see cref="License"/>. Regular and
/// bold only: nothing in the report is set in italic, and each face is 400 KB.
/// A request for italic is answered with the upright face rather than refused,
/// because a missing glyph is a broken document and a missing slant is not.
/// </para>
/// </remarks>
public sealed class ReportFonts : IFontResolver
{
    public const string Family = "Liberation Sans";

    private const string Regular = "font.LiberationSans-Regular.ttf";
    private const string Bold = "font.LiberationSans-Bold.ttf";

    /// <summary>
    /// Installs these fonts as the process's resolver, once.
    /// </summary>
    /// <remarks>
    /// PDFsharp keeps the resolver in a static, and assigning it twice throws
    /// once anything has been rendered. Every entry point that renders a PDF
    /// calls this, so it has to be safe to call repeatedly and from more than
    /// one thread - a web request and a scheduled run can arrive together.
    /// </remarks>
    public static void Install()
    {
        lock (Gate)
        {
            if (_installed) { return; }

            GlobalFontSettings.FontResolver = new ReportFonts();
            _installed = true;
        }
    }

    private static readonly object Gate = new();
    private static bool _installed;

    /// <summary>The font licence, for anywhere that has to reproduce it.</summary>
    public static string License => Read("font.LICENSE.txt") is { } bytes
        ? System.Text.Encoding.UTF8.GetString(bytes)
        : "";

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic)
    {
        // The family is ignored on purpose. This product draws one document
        // with one family; answering only to its own name would leave anything
        // MigraDoc defaults to unresolved, which fails at render time with a
        // message about a font nobody chose.
        _ = familyName;
        _ = italic;

        return new FontResolverInfo(bold ? Bold : Regular);
    }

    public byte[]? GetFont(string faceName) => Read(faceName);

    private static byte[]? Read(string name)
    {
        using var stream = typeof(ReportFonts).GetTypeInfo().Assembly.GetManifestResourceStream(name);
        if (stream is null) { return null; }

        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}
