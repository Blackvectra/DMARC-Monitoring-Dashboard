using System.IO.Compression;
using System.Text;
using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// Getting report text out of an email attachment.
///
/// Anchored on the attachments exactly as they arrived in a real DMARC
/// mailbox: two zips and two gzips, from Google, Outlook and gosecure.net.
/// The compressed originals are kept alongside the extracted XML so this
/// tests the real path rather than a tidied-up version of it.
///
/// Everything here treats the attachment as hostile, because anyone on the
/// internet can send mail to a published rua address.
/// </summary>
public sealed class ReportAttachmentTests
{
    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    // ---- the real attachments -----------------------------------------------

    [Fact]
    public void ExtractsAZippedGoogleAggregateReport()
    {
        var reports = ReportAttachment.Extract("google.zip", Fixture("google-aggregate.zip"));

        var r = Assert.Single(reports);
        Assert.Equal(ReportKind.DmarcAggregate, r.Kind);
        Assert.Contains("nrgtechservices.com", r.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractsAZippedGoSecureReport()
    {
        var reports = ReportAttachment.Extract("gosecure.xml.zip", Fixture("gosecure-aggregate.xml.zip"));

        var r = Assert.Single(reports);
        Assert.Equal(ReportKind.DmarcAggregate, r.Kind);
        Assert.Contains("gosecure.net", r.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractsAGzippedOutlookAggregateReport()
    {
        var reports = ReportAttachment.Extract("outlook.xml.gz", Fixture("outlook-aggregate.xml.gz"));

        var r = Assert.Single(reports);
        Assert.Equal(ReportKind.DmarcAggregate, r.Kind);
        Assert.Contains("Enterprise Outlook", r.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractsAGzippedTlsReport()
    {
        var reports = ReportAttachment.Extract("google.json.gz", Fixture("google-tlsrpt.json.gz"));

        var r = Assert.Single(reports);
        Assert.Equal(ReportKind.TlsRpt, r.Kind);
        Assert.Contains("policies", r.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void RecoversTheInnerNameFromAGzipAttachment()
    {
        var r = Assert.Single(ReportAttachment.Extract("outlook.xml.gz", Fixture("outlook-aggregate.xml.gz")));
        Assert.Equal("outlook.xml", r.FileName);
    }

    [Fact]
    public void ExtractedContentMatchesTheUncompressedFixtureExactly()
    {
        // Proves the decompression path is lossless rather than merely
        // producing something that happens to parse.
        var fromGz = Assert.Single(ReportAttachment.Extract("x.gz", Fixture("outlook-aggregate.xml.gz")));
        var direct = Encoding.UTF8.GetString(Fixture("outlook-aggregate.xml"));

        Assert.Equal(direct.Trim(), fromGz.Content.Trim());
    }

    // ---- classification by content, not by name -----------------------------

    [Fact]
    public void ClassifiesByContentRatherThanExtension()
    {
        // Real receivers disagree about naming. One sample from Google is
        // "...json.gz" and another from the same domain the same day is
        // "...xml.gz". A DMARC report named .json must still be DMARC.
        var xml = Fixture("google-aggregate.xml");

        var asJson = Assert.Single(ReportAttachment.Extract("report.json", xml));
        Assert.Equal(ReportKind.DmarcAggregate, asJson.Kind);

        var noExtension = Assert.Single(ReportAttachment.Extract("report", xml));
        Assert.Equal(ReportKind.DmarcAggregate, noExtension.Kind);
    }

    [Fact]
    public void DetectsCompressionByMagicNumberNotExtension()
    {
        // A gzip attachment mislabelled .xml must still be decompressed.
        var reports = ReportAttachment.Extract("mislabelled.xml", Fixture("outlook-aggregate.xml.gz"));
        Assert.Equal(ReportKind.DmarcAggregate, Assert.Single(reports).Kind);
    }

    [Theory]
    [InlineData("<feedback><report_metadata/></feedback>", ReportKind.DmarcAggregate)]
    [InlineData("""{"policies":[]}""", ReportKind.TlsRpt)]
    [InlineData("<html><body>hi</body></html>", ReportKind.Unknown)]
    [InlineData("""{"something":"else"}""", ReportKind.Unknown)]
    [InlineData("just text", ReportKind.Unknown)]
    [InlineData("", ReportKind.Unknown)]
    public void ClassifiesContent(string content, ReportKind expected)
    {
        Assert.Equal(expected, ReportAttachment.Classify(content));
    }

    [Fact]
    public void ClassifiesDespiteLeadingWhitespaceAndDeclaration()
    {
        const string xml = "\n\n  <?xml version=\"1.0\"?>\n<feedback></feedback>";
        Assert.Equal(ReportKind.DmarcAggregate, ReportAttachment.Classify(xml));
    }

    [Fact]
    public void StripsAByteOrderMark()
    {
        // A BOM left in place lands before the XML declaration and makes an
        // otherwise valid report unparseable.
        var withBom = new byte[] { 0xEF, 0xBB, 0xBF }
            .Concat(Encoding.UTF8.GetBytes("<feedback><report_metadata/></feedback>"))
            .ToArray();

        var r = Assert.Single(ReportAttachment.Extract("bom.xml", withBom));
        Assert.StartsWith("<feedback", r.Content, StringComparison.Ordinal);
    }

    // ---- things that are not reports ----------------------------------------

    [Fact]
    public void IgnoresAnAttachmentThatIsNotAReport()
    {
        // Mailboxes receive signatures, images and auto-replies.
        var jpeg = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10 };
        Assert.Empty(ReportAttachment.Extract("logo.jpg", jpeg));
    }

    [Fact]
    public void IgnoresAnEmptyAttachment()
    {
        Assert.Empty(ReportAttachment.Extract("empty.gz", []));
    }

    [Fact]
    public void IgnoresAZipContainingNothingUseful()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var e = zip.CreateEntry("readme.txt");
            using var w = new StreamWriter(e.Open());
            w.Write("nothing to see here");
        }
        Assert.Empty(ReportAttachment.Extract("junk.zip", ms.ToArray()));
    }

    [Fact]
    public void NeverThrowsOnCorruptInput()
    {
        // One bad attachment must not stop a run working through a backlog.
        byte[][] nasty =
        [
            [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00],                    // truncated zip header
            [0x1F, 0x8B, 0x08, 0x00, 0xFF, 0xFF, 0xFF],              // truncated gzip
            Encoding.UTF8.GetBytes("<feedback"),                      // truncated xml
            [0x00, 0x00, 0x00, 0x00],
            Enumerable.Repeat((byte)0x41, 100_000).ToArray(),
        ];

        foreach (var input in nasty)
        {
            Assert.Null(Record.Exception(() => ReportAttachment.Extract("x", input)));
        }
    }

    [Fact]
    public void RejectsNullContentLoudlyRatherThanSilently()
    {
        // A null here is a caller bug, not hostile input, and hiding it would
        // turn a mistake into a mailbox that silently processes nothing.
        Assert.Throws<ArgumentNullException>(() => ReportAttachment.Extract("x", null!));
    }

    // ---- hostile input ------------------------------------------------------

    [Fact]
    public void RefusesAGzipBomb()
    {
        // Highly compressible input that expands past the cap. A few hundred
        // bytes on the wire becoming gigabytes in memory is how an ingest run
        // gets killed by the OOM killer.
        //
        // The payload is deliberately a VALID report shape wrapped around the
        // padding. An earlier version of this test used a block of zero bytes,
        // which is not a report, so it was discarded by classification and the
        // assertion passed whether or not the cap existed. Mutation testing
        // caught that: removing the cap left the suite green. The bomb has to
        // be something that would be accepted if it got through.
        var padding = Encoding.UTF8.GetBytes(new string('A', ReportAttachment.MaxDecompressedBytes + (1024 * 1024)));
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gz.Write(Encoding.UTF8.GetBytes("<feedback><report_metadata><org_name>"));
            gz.Write(padding, 0, padding.Length);
            gz.Write(Encoding.UTF8.GetBytes("</org_name></report_metadata></feedback>"));
        }

        var compressed = ms.ToArray();
        Assert.True(compressed.Length < 1024 * 1024, "the bomb should be small on the wire");
        Assert.Empty(ReportAttachment.Extract("bomb.gz", compressed));
    }

    [Fact]
    public void AcceptsALargeButLegitimateReport()
    {
        // The cap must not be so eager that a real report from a large
        // receiver is discarded. The biggest real sample here is under 100 KB;
        // this is an order of magnitude larger and must still come through.
        var body = "<feedback><report_metadata><org_name>"
            + new string('A', 2 * 1024 * 1024)
            + "</org_name></report_metadata></feedback>";

        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            gz.Write(bytes, 0, bytes.Length);
        }

        var r = Assert.Single(ReportAttachment.Extract("big-but-real.gz", ms.ToArray()));
        Assert.Equal(ReportKind.DmarcAggregate, r.Kind);
    }

    [Fact]
    public void ReturnsNothingRatherThanATruncatedReportWhenTheCapIsHit()
    {
        // Truncated XML parses into plausible-looking nonsense. Reporting
        // nonsense to a customer is worse than reporting nothing.
        var oversized = Encoding.UTF8.GetBytes(
            "<feedback>" + new string('x', ReportAttachment.MaxDecompressedBytes + 1000) + "</feedback>");

        Assert.Empty(ReportAttachment.Extract("big.xml", oversized));
    }

    [Fact]
    public void StopsAfterTheArchiveEntryLimit()
    {
        // A zip with thousands of tiny entries costs time rather than memory.
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (var i = 0; i < ReportAttachment.MaxArchiveEntries + 50; i++)
            {
                var e = zip.CreateEntry($"r{i}.xml");
                using var w = new StreamWriter(e.Open());
                w.Write("<feedback><report_metadata/></feedback>");
            }
        }

        var extracted = ReportAttachment.Extract("many.zip", ms.ToArray());
        Assert.True(extracted.Count <= ReportAttachment.MaxArchiveEntries);
    }

    [Fact]
    public void NeverSurfacesATraversalPathAsAFileName()
    {
        // Nothing here writes to disk, but the name reaches logs and reports,
        // so it must not carry a path out of anywhere.
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var e = zip.CreateEntry("../../../etc/evil.xml");
            using var w = new StreamWriter(e.Open());
            w.Write("<feedback><report_metadata/></feedback>");
        }

        var r = Assert.Single(ReportAttachment.Extract("evil.zip", ms.ToArray()));
        Assert.DoesNotContain("..", r.FileName, StringComparison.Ordinal);
        Assert.DoesNotContain("/", r.FileName, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractsEveryReportFromAMultiReportArchive()
    {
        // Rare, but some senders batch. Taking only the first would silently
        // discard a receiver's view of a domain.
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var n in new[] { "a.xml", "b.xml" })
            {
                var e = zip.CreateEntry(n);
                using var w = new StreamWriter(e.Open());
                w.Write("<feedback><report_metadata/></feedback>");
            }
        }

        Assert.Equal(2, ReportAttachment.Extract("batch.zip", ms.ToArray()).Count);
    }
}
