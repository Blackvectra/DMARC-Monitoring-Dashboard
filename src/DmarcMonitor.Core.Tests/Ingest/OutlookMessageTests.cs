using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// A report saved by dragging its message out of Outlook, rather than by the
/// exporter. It used to be counted as "not a report" and lost.
/// </summary>
public sealed class OutlookMessageTests
{
    private const string Xml =
        "<feedback><report_metadata><report_id>from-msg</report_id></report_metadata></feedback>";

    [Fact]
    public void TheReportInsideAMessageIsExtracted()
    {
        var msg = Message(("google.com!example.com!1!2.xml.gz", Gzip(Xml)));

        var report = Assert.Single(ReportAttachment.Extract("stray.msg", msg));

        Assert.Equal(ReportKind.DmarcAggregate, report.Kind);
        Assert.Contains("from-msg", report.Content, StringComparison.Ordinal);
        Assert.Equal("google.com!example.com!1!2.xml", report.FileName);
    }

    /// <summary>
    /// The usual case in a real .msg: an attachment under 4 KB lives in the
    /// mini stream, not in ordinary sectors.
    /// </summary>
    [Fact]
    public void ASmallAttachmentInTheMiniStreamIsExtracted()
    {
        var msg = Message(mini: true, ("google.com!example.com!1!2.xml.gz", Gzip(Xml)), ("b.xml", Encoding.UTF8.GetBytes(Xml.Replace("from-msg", "b", StringComparison.Ordinal))));

        var reports = ReportAttachment.Extract("small.msg", msg);

        Assert.Equal(2, reports.Count);
        Assert.Contains(reports, r => r.Content.Contains("from-msg", StringComparison.Ordinal));
        Assert.Contains(reports, r => r.FileName == "google.com!example.com!1!2.xml");
    }

    [Fact]
    public void EveryAttachmentIsRead()
    {
        var msg = Message(("a.xml", Encoding.UTF8.GetBytes(Xml.Replace("from-msg", "a", StringComparison.Ordinal))),
                          ("b.xml.gz", Gzip(Xml.Replace("from-msg", "b", StringComparison.Ordinal))));

        Assert.Equal(2, ReportAttachment.Extract("two.msg", msg).Count);
    }

    [Fact]
    public void AMessageWithNoReportIsNotOne()
    {
        var msg = Message(("photo.jpg", [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3]));

        Assert.Empty(ReportAttachment.Extract("holiday.msg", msg));
    }

    /// <summary>Damage is named, not passed off as "not a report".</summary>
    [Fact]
    public void ADamagedMessageIsSaidToBeUnreadable()
    {
        var msg = Message(("a.xml", Encoding.UTF8.GetBytes(Xml)));
        var cut = msg[..700];   // header and part of the FAT; the directory is gone
        var budget = ExtractionBudget.ForOperator();

        Assert.Empty(ReportAttachment.ExtractAll("cut.msg", cut, budget).ToList());
        Assert.Contains(budget.Unreadable, u => u.Contains("Outlook message", StringComparison.Ordinal));
    }

    [Fact]
    public void ASectorChainThatLoopsEnds()
    {
        // Longer than one sector, so the chain has a next link to follow.
        var msg = Message(("a.xml", Encoding.UTF8.GetBytes(Xml.Replace("from-msg", new string('x', 2000), StringComparison.Ordinal))));

        // Point the first data sector's FAT entry back at itself.
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(512 + (2 * 4)), 2);
        var budget = ExtractionBudget.ForOperator();

        Assert.Empty(ReportAttachment.ExtractAll("loop.msg", msg, budget).ToList());
        Assert.NotEmpty(budget.Unreadable);
    }

    private static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true)) { gz.Write(Encoding.UTF8.GetBytes(text)); }
        return ms.ToArray();
    }

    /// <summary>
    /// A minimal .msg: one compound file, 512-byte sectors, a mini-stream
    /// cutoff of zero so every stream lives in ordinary sectors - or, with
    /// <paramref name="mini"/>, all of them in the mini stream - and one
    /// attachment storage per file holding its data and long file name.
    /// </summary>
    private static byte[] Message(params (string Name, byte[] Data)[] attachments) => Message(false, attachments);

    private static byte[] Message(bool mini, params (string Name, byte[] Data)[] attachments)
    {
        const int S = 512;
        const uint End = 0xFFFFFFFE, Free = 0xFFFFFFFF, FatSect = 0xFFFFFFFD;

        var streams = new List<byte[]>();
        var entries = new List<(string Name, byte Type, uint Left, uint Right, uint Child, int Stream)>
        {
            ("Root Entry", 5, Free, Free, attachments.Length > 0 ? 1u : Free, -1),
        };

        for (var i = 0; i < attachments.Length; i++)
        {
            var storage = (uint)entries.Count;
            entries.Add(($"__attach_version1.0_#{i:X8}", 1, Free, i + 1 < attachments.Length ? storage + 3 : Free, storage + 1, -1));
            streams.Add(attachments[i].Data);
            entries.Add(("__substg1.0_37010102", 2, Free, storage + 2, Free, streams.Count - 1));
            streams.Add(Encoding.Unicode.GetBytes(attachments[i].Name + "\0"));
            entries.Add(("__substg1.0_3707001F", 2, Free, Free, Free, streams.Count - 1));
        }

        var dirSectors = ((entries.Count * 128) + S - 1) / S;
        var fat = new List<uint> { FatSect };                    // sector 0: the FAT
        for (var i = 0; i < dirSectors; i++) { fat.Add(i + 1 < dirSectors ? (uint)fat.Count + 1 : End); }

        var starts = new List<uint>();
        byte[] miniStream = [];
        var miniFat = new List<uint>();
        uint miniStreamStart = End, miniFatStart = End;

        if (mini)
        {
            // Every stream into 64-byte mini sectors, chained by the mini FAT;
            // the mini stream itself is the root entry's ordinary stream.
            using var ms = new MemoryStream();
            foreach (var s in streams)
            {
                starts.Add((uint)miniFat.Count);
                var n = Math.Max(1, (s.Length + 63) / 64);
                for (var i = 0; i < n; i++) { miniFat.Add(i + 1 < n ? (uint)miniFat.Count + 1 : End); }
                var padded = new byte[n * 64];
                s.CopyTo(padded, 0);
                ms.Write(padded);
            }

            miniStream = ms.ToArray();
            miniFatStart = (uint)fat.Count;
            fat.Add(End);                                         // one mini FAT sector
            miniStreamStart = (uint)fat.Count;
            var m = (miniStream.Length + S - 1) / S;
            for (var i = 0; i < m; i++) { fat.Add(i + 1 < m ? (uint)fat.Count + 1 : End); }
        }
        else
        {
            foreach (var s in streams)
            {
                starts.Add((uint)fat.Count);
                var n = Math.Max(1, (s.Length + S - 1) / S);
                for (var i = 0; i < n; i++) { fat.Add(i + 1 < n ? (uint)fat.Count + 1 : End); }
            }
        }

        if (fat.Count > S / 4) { throw new InvalidOperationException("the test builder holds one FAT sector"); }
        while (fat.Count < S / 4) { fat.Add(Free); }

        var file = new byte[S * (1 + fat.FindLastIndex(f => f != Free) + 1)];

        // Header.
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(file, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x18), 0x3E);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x1A), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x1C), 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x1E), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x20), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x2C), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x30), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x38), mini ? 4096u : 0);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x3C), miniFatStart);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x40), mini ? 1u : 0);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x44), End);
        for (var i = 0; i < 109; i++) { BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x4C + (i * 4)), i == 0 ? 0 : Free); }

        for (var i = 0; i < fat.Count; i++) { BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(S + (i * 4)), fat[i]); }

        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            var d = file.AsSpan(S * 2 + (i * 128), 128);
            var name = Encoding.Unicode.GetBytes(e.Name + "\0");
            name.CopyTo(d);
            BinaryPrimitives.WriteUInt16LittleEndian(d[0x40..], (ushort)name.Length);
            d[0x42] = e.Type;
            BinaryPrimitives.WriteUInt32LittleEndian(d[0x44..], e.Left);
            BinaryPrimitives.WriteUInt32LittleEndian(d[0x48..], e.Right);
            BinaryPrimitives.WriteUInt32LittleEndian(d[0x4C..], e.Child);
            var isRoot = i == 0;
            BinaryPrimitives.WriteUInt32LittleEndian(d[0x74..], e.Stream >= 0 ? starts[e.Stream] : isRoot ? miniStreamStart : End);
            BinaryPrimitives.WriteUInt32LittleEndian(d[0x78..], e.Stream >= 0 ? (uint)streams[e.Stream].Length : isRoot ? (uint)miniStream.Length : 0);
        }

        if (mini)
        {
            for (var i = 0; i < S / 4; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(S * (1 + (int)miniFatStart) + (i * 4)), i < miniFat.Count ? miniFat[i] : Free);
            }

            miniStream.CopyTo(file, S * (1 + (int)miniStreamStart));
        }
        else
        {
            for (var i = 0; i < streams.Count; i++) { streams[i].CopyTo(file, S * (1 + (int)starts[i])); }
        }

        return file;
    }
}
