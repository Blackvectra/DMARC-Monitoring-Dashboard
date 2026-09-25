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
        // A gzip attachment mislabeled .xml must still be decompressed.
        var reports = ReportAttachment.Extract("mislabeled.xml", Fixture("outlook-aggregate.xml.gz"));
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
            DamagedListOfContents(Zip("r.xml", Report("r"))),       // opens, then throws on Entries
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

    // ---- what a mailbox export actually looks like -------------------------

    /// <summary>A zip holding attachments as they arrived: gzipped, zipped, bare.</summary>
    private static byte[] ExportZip(int gzipped = 0, int zipped = 0, int bare = 0)
    {
        using var outer = new MemoryStream();
        using (var zip = new ZipArchive(outer, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (var i = 0; i < gzipped; i++) { Put(zip, $"gz{i}.xml.gz", Gzip(Report($"gz{i}"))); }
            for (var i = 0; i < zipped; i++) { Put(zip, $"z{i}.xml.zip", Zip($"z{i}.xml", Report($"z{i}"))); }
            for (var i = 0; i < bare; i++) { Put(zip, $"b{i}.xml", Encoding.UTF8.GetBytes(Report($"b{i}"))); }
        }
        return outer.ToArray();
    }

    private static string Report(string id) =>
        $"<feedback><report_metadata><report_id>{id}</report_id></report_metadata></feedback>";

    private static void Put(ZipArchive zip, string name, byte[] content)
    {
        using var s = zip.CreateEntry(name).Open();
        s.Write(content);
    }

    private static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(Encoding.UTF8.GetBytes(text));
        }
        return ms.ToArray();
    }

    private static byte[] Zip(string name, string text)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            Put(zip, name, Encoding.UTF8.GetBytes(text));
        }
        return ms.ToArray();
    }

    [Fact]
    public void ReadsAnExportZipOfAttachmentsAsTheyArrived()
    {
        // The thing somebody actually drags onto the page: a mailbox export,
        // which is a zip OF the attachments, each still gzipped or zipped as
        // its receiver sent it. Read one level deep this finds nothing at all,
        // because what is inside the zip is not XML, it is more gzip.
        var reports = ReportAttachment.ExtractAll(
            "dmarc-export.zip", ExportZip(gzipped: 4, zipped: 3, bare: 2), ExtractionBudget.ForOperator()).ToList();

        Assert.Equal(9, reports.Count);
        Assert.All(reports, r => Assert.Equal(ReportKind.DmarcAggregate, r.Kind));

        // Named for the report inside, not for the export it came in.
        Assert.Contains(reports, r => r.FileName == "gz0.xml");
        Assert.Contains(reports, r => r.FileName == "z0.xml");
        Assert.DoesNotContain(reports, r => r.FileName.Contains("export", StringComparison.Ordinal));
    }

    [Fact]
    public void AnExportLargerThanTheMailBudgetStillComesInForAnOperator()
    {
        // 100 reports is nothing for an export and far past what an email
        // attachment is allowed. The difference is who the file came from.
        var export = ExportZip(gzipped: 100);

        Assert.Equal(100, ReportAttachment.ExtractAll("export.zip", export, ExtractionBudget.ForOperator()).Count());
        Assert.True(ReportAttachment.Extract("export.zip", export).Count <= ReportAttachment.MaxArchiveEntries);
    }

    [Fact]
    public void SaysSoWhenItRanOutRatherThanReturningWhatFitted()
    {
        // The whole point of the budget being the caller's. An export cut off
        // half way that reports success is a client reported on with half
        // their mail missing, and nobody ever finds out.
        var budget = new ExtractionBudget(entries: 5, bytes: ExtractAll.Plenty);

        var reports = ReportAttachment.ExtractAll("export.zip", ExportZip(gzipped: 20), budget).ToList();

        Assert.Equal(5, reports.Count);
        Assert.True(budget.Exhausted);
    }

    [Fact]
    public void DoesNotClaimItRanOutWhenEverythingFitted()
    {
        var budget = new ExtractionBudget(entries: 50, bytes: ExtractAll.Plenty);

        Assert.Equal(6, ReportAttachment.ExtractAll("export.zip", ExportZip(gzipped: 6), budget).Count());
        Assert.False(budget.Exhausted);
    }

    [Fact]
    public void TheByteBudgetIsSpentOnWhatArrivedNotOnWhatTheArchiveClaimed()
    {
        // A zip bomb declares whatever gets it past a length check, so the
        // budget is charged as the bytes come out of the stream.
        var budget = new ExtractionBudget(entries: 100, bytes: 200);

        var reports = ReportAttachment.ExtractAll("export.zip", ExportZip(gzipped: 20), budget).ToList();

        Assert.True(budget.Exhausted);
        Assert.True(reports.Count < 20);
    }

    [Fact]
    public void StopsFollowingArchivesThatGoOnForever()
    {
        // A zip inside a zip inside a zip, and so on. Terminates rather than
        // recursing until the stack gives out.
        var payload = Zip("r.xml", Report("deep"));
        for (var i = 0; i < ReportAttachment.MaxArchiveDepth + 3; i++)
        {
            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                Put(zip, $"layer{i}.zip", payload);
            }
            payload = ms.ToArray();
        }

        Assert.Empty(ReportAttachment.ExtractAll("nested.zip", payload, ExtractionBudget.ForOperator()));
    }

    [Fact]
    public void ADeadEntryDoesNotCostAnotherEntryItsPlace()
    {
        // Empty and unreadable members are common in a real export. Charging
        // the budget for them would cut a legitimate export short.
        using var outer = new MemoryStream();
        using (var zip = new ZipArchive(outer, ZipArchiveMode.Create, leaveOpen: true))
        {
            zip.CreateEntry("empty.xml");
            Put(zip, "notes.txt", Encoding.UTF8.GetBytes("nothing to see"));
            Put(zip, "real.xml.gz", Gzip(Report("real")));
        }

        var budget = new ExtractionBudget(entries: 2, bytes: ExtractAll.Plenty);
        var reports = ReportAttachment.ExtractAll("mixed.zip", outer.ToArray(), budget).ToList();

        Assert.Equal("real.xml", Assert.Single(reports).FileName);
        Assert.False(budget.Exhausted);
    }

    private static class ExtractAll
    {
        public const long Plenty = 64L * 1024 * 1024;
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

    // ---- what could not be read is said, not dropped -------------------------
    //
    // An empty result used to be the answer to a zip of holiday photos and to a
    // damaged export alike, so a caller could not tell "nothing here" from "a
    // report here that could not be read". The budget now carries the second.

    /// <summary>
    /// A zip whose end record is intact and whose list of contents is not.
    /// </summary>
    /// <remarks>
    /// ZipArchive opens this without complaint and throws only when the
    /// entries are first read - which is exactly what escaped the old try and
    /// ended a whole folder import.
    /// </remarks>
    private static byte[] DamagedListOfContents(byte[] zip) => SyntheticReports.WithDamagedListOfContents(zip);

    /// <summary>
    /// A zip whose named member's compressed data is damaged: its first
    /// deflate block claims the reserved block type, which no reader accepts.
    /// </summary>
    private static byte[] DamageMember(byte[] zip, string name)
    {
        var copy = zip.ToArray();
        var span = copy.AsSpan();
        var from = 0;

        while (true)
        {
            var at = span[from..].IndexOf([(byte)0x50, (byte)0x4B, (byte)0x03, (byte)0x04]);
            Assert.True(at >= 0, $"no member named {name}");
            at += from;

            var nameLength = BitConverter.ToUInt16(copy, at + 26);
            var extraLength = BitConverter.ToUInt16(copy, at + 28);
            if (Encoding.UTF8.GetString(copy, at + 30, nameLength) == name)
            {
                copy[at + 30 + nameLength + extraLength] = 0xFF;
                return copy;
            }

            from = at + 4;
        }
    }

    /// <summary>An export of three reports, the middle one deflated so it can be damaged.</summary>
    private static byte[] ExportOfThree()
    {
        using var outer = new MemoryStream();
        using (var zip = new ZipArchive(outer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Put(zip, "first.xml.gz", Gzip(Report("first")));
            using (var s = zip.CreateEntry("broken.xml", CompressionLevel.Optimal).Open())
            {
                s.Write(Encoding.UTF8.GetBytes(Report("broken")));
            }
            Put(zip, "last.xml.gz", Gzip(Report("last")));
        }
        return outer.ToArray();
    }

    private static byte[] ZipOf(string name, byte[] content)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            Put(zip, name, content);
        }
        return ms.ToArray();
    }

    [Fact]
    public void AZipWhoseListOfContentsIsDamagedIsRecordedRatherThanThrown()
    {
        var budget = ExtractionBudget.ForOperator();

        var reports = ReportAttachment.ExtractAll("export.zip", DamagedListOfContents(Zip("r.xml", Report("r"))), budget).ToList();

        Assert.Empty(reports);
        Assert.Contains("could not be opened as a zip archive", Assert.Single(budget.Unreadable), StringComparison.Ordinal);
    }

    [Fact]
    public void AZipCutShortIsRecordedAsUnreadableNotAsNoReport()
    {
        var zip = Zip("r.xml", Report("r"));
        var budget = ExtractionBudget.ForOperator();

        Assert.Empty(ReportAttachment.ExtractAll("export.zip", zip[..(zip.Length / 2)], budget));
        Assert.Single(budget.Unreadable);
    }

    [Theory]
    [InlineData("in the header")]
    [InlineData("half way")]
    [InlineData("in the trailer")]
    public void AGzipCutShortIsRecordedRatherThanReadAsAShorterReport(string where)
    {
        // GZipStream does not complain about any of these: it returns what it
        // had decoded when the bytes ran out. Cut in half, that is the first
        // half of a report; cut early, nothing at all, which used to read as
        // "not a report". Cut in the trailer the report inside would read
        // whole, but nothing can tell that from the file, so it is not what was
        // sent and is said to be so.
        var whole = Gzip(Report("cut"));
        var cut = where switch
        {
            "in the header" => whole[..6],
            "half way" => whole[..(whole.Length / 2)],
            _ => whole[..^1],
        };
        var budget = ExtractionBudget.ForOperator();

        Assert.Empty(ReportAttachment.ExtractAll("report.xml.gz", cut, budget));
        Assert.Contains("cut short", Assert.Single(budget.Unreadable), StringComparison.Ordinal);
    }

    [Fact]
    public void AGzipWithSomethingAfterItIsStillWhole()
    {
        // A newline or padding after the gzip data decompresses to the whole
        // report, so the check for a file cut short must not refuse it.
        var whole = Gzip(Report("padded"));

        foreach (var trailing in new[] { Encoding.ASCII.GetBytes("\r\n"), new byte[16] })
        {
            var budget = ExtractionBudget.ForOperator();
            var r = Assert.Single(ReportAttachment.ExtractAll("report.xml.gz", [.. whole, .. trailing], budget));
            Assert.Contains("padded", r.Content, StringComparison.Ordinal);
            Assert.Empty(budget.Unreadable);
        }
    }

    [Fact]
    public void AGzipOfSeveralMembersIsStillRead()
    {
        // Legal, and read as all of its members joined. Its trailer describes
        // only the last one, so it must not be mistaken for a file cut short.
        var text = Report("two-members");
        var half = text.Length / 2;
        var budget = ExtractionBudget.ForOperator();

        var r = Assert.Single(ReportAttachment.ExtractAll(
            "report.xml.gz", [.. Gzip(text[..half]), .. Gzip(text[half..])], budget));

        Assert.Equal(text, r.Content);
        Assert.Empty(budget.Unreadable);
    }

    [Fact]
    public void ADamagedMemberIsNamedAndTheRestOfTheExportStillComesOut()
    {
        var budget = ExtractionBudget.ForOperator();
        var reports = ReportAttachment.ExtractAll("export.zip", DamageMember(ExportOfThree(), "broken.xml"), budget).ToList();

        Assert.Equal(["first.xml", "last.xml"], reports.Select(r => r.FileName));
        Assert.StartsWith("broken.xml: could not be decompressed", Assert.Single(budget.Unreadable), StringComparison.Ordinal);
    }

    [Fact]
    public void TheSameExportUndamagedGivesUpAllThree()
    {
        // The control for the test above: without the damage, the member it
        // names is read like the others.
        var budget = ExtractionBudget.ForOperator();

        Assert.Equal(3, ReportAttachment.ExtractAll("export.zip", ExportOfThree(), budget).Count());
        Assert.Empty(budget.Unreadable);
    }

    [Fact]
    public void AGzipCutShortInsideAnExportIsNamedForItself()
    {
        var gz = Gzip(Report("inner"));
        var budget = ExtractionBudget.ForOperator();

        var reports = ReportAttachment.ExtractAll("export.zip", ZipOf("inner.xml.gz", gz[..(gz.Length / 2)]), budget).ToList();

        Assert.Empty(reports);
        Assert.StartsWith("inner.xml.gz: cut short", Assert.Single(budget.Unreadable), StringComparison.Ordinal);
    }

    [Fact]
    public void AReportTooLargeToReadIsRecordedRatherThanDropped()
    {
        var oversized = Encoding.UTF8.GetBytes(
            "<feedback>" + new string('x', ReportAttachment.MaxDecompressedBytes + 1000) + "</feedback>");
        var budget = ExtractionBudget.ForOperator();

        Assert.Empty(ReportAttachment.ExtractAll("big.xml", oversized, budget));
        Assert.Contains("larger than", Assert.Single(budget.Unreadable), StringComparison.Ordinal);
    }

    [Fact]
    public void NothingIsRecordedForAFileThatIsSimplyNotAReport()
    {
        // The distinction the importer rests on: a readable file with no
        // report in it is not a failure, and must not become one.
        foreach (var (name, content) in new (string, byte[])[]
                 {
                     ("notes.txt", Encoding.UTF8.GetBytes("nothing to see")),
                     ("readme.zip", Zip("readme.txt", "hello")),
                     ("logo.jpg", [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
                     ("empty.xml", []),
                 })
        {
            var budget = ExtractionBudget.ForOperator();
            Assert.Empty(ReportAttachment.ExtractAll(name, content, budget));
            Assert.Empty(budget.Unreadable);
        }
    }

}
