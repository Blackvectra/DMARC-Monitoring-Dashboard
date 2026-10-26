using System.Buffers.Binary;
using System.Text;

namespace DmarcMonitor.Core.Ingest;

/// <summary>
/// Reads the attachments out of an Outlook <c>.msg</c> file.
/// </summary>
/// <remarks>
/// <para>
/// Reports reach the importer this way when somebody drags one out of Outlook
/// instead of letting the exporter save its attachment, which is what happens
/// to a stray report that arrived after the export ran. Before this the file
/// was counted as "not a report" and the report inside it was lost.
/// </para>
/// <para>
/// A .msg is a Compound File Binary container ([MS-CFB]) holding MAPI
/// properties ([MS-OXMSG]). Only what an attachment needs is read: each
/// <c>__attach_version1.0_#</c> storage's data stream (PR_ATTACH_DATA_BIN)
/// and its file name. Written here rather than taken as a package because it
/// is two hundred lines against a dependency on the import path of hostile
/// files, and every offset is bounds-checked: the input is whatever was mailed
/// to the reporting address.
/// </para>
/// </remarks>
internal static class OutlookMessage
{
    private static readonly byte[] Signature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint NoStream = 0xFFFFFFFF;
    private const int EntrySize = 128;

    /// <summary>Whether the bytes are a compound file, which a .msg is.</summary>
    public static bool LooksLikeOne(byte[] b) => b.Length >= 512 && b.AsSpan(0, 8).SequenceEqual(Signature);

    /// <summary>One attachment: its file name and its bytes.</summary>
    public readonly record struct Attachment(string Name, byte[] Content);

    /// <summary>
    /// The attachments, or an exception saying why the container is damaged.
    /// </summary>
    /// <param name="maxBytes">The most any one attachment may claim to be.</param>
    public static IReadOnlyList<Attachment> ReadAttachments(byte[] file, int maxBytes)
    {
        var cfb = new CompoundFile(file);
        var found = new List<Attachment>();

        foreach (var storage in cfb.Children(0))
        {
            var entry = cfb.Entry(storage);
            if (entry.Type != 1 || !entry.Name.StartsWith("__attach_version1.0_#", StringComparison.OrdinalIgnoreCase)) { continue; }

            byte[]? data = null;
            string? longName = null, shortName = null;

            foreach (var child in cfb.Children(storage))
            {
                var c = cfb.Entry(child);
                if (c.Type != 2) { continue; }

                // PR_ATTACH_DATA_BIN, PR_ATTACH_LONG_FILENAME, PR_ATTACH_FILENAME.
                switch (c.Name.ToUpperInvariant())
                {
                    case "__SUBSTG1.0_37010102":
                        if (c.Size > (ulong)maxBytes) { throw new InvalidDataException($"an attachment claims {c.Size:N0} bytes"); }
                        data = cfb.Read(c);
                        break;
                    case "__SUBSTG1.0_3707001F":
                        longName = Unicode(cfb.Read(c));
                        break;
                    case "__SUBSTG1.0_3704001F":
                        shortName = Unicode(cfb.Read(c));
                        break;
                }
            }

            // An embedded message (attach method 5) has no data stream. Not
            // followed: reports are never sent that way.
            if (data is { Length: > 0 })
            {
                found.Add(new Attachment(longName ?? shortName ?? entry.Name, data));
            }
        }

        return found;
    }

    private static string Unicode(byte[] b) => Encoding.Unicode.GetString(b).TrimEnd('\0');

    private readonly record struct DirEntry(string Name, int Type, uint Left, uint Right, uint Child, uint Start, ulong Size);

    /// <summary>Just enough of [MS-CFB] to find streams and read them.</summary>
    private sealed class CompoundFile
    {
        private readonly byte[] _b;
        private readonly int _sectorSize;
        private readonly int _miniSectorSize;
        private readonly uint _miniCutoff;
        private readonly uint[] _fat;
        private readonly uint[] _miniFat;
        private readonly byte[] _dir;
        private readonly byte[] _miniStream;

        public CompoundFile(byte[] b)
        {
            _b = b;
            var sectorShift = U16(0x1E);
            var miniShift = U16(0x20);
            if (sectorShift is not (9 or 12) || miniShift != 6) { throw new InvalidDataException("not a compound file this reads"); }

            _sectorSize = 1 << sectorShift;
            _miniSectorSize = 1 << miniShift;
            _miniCutoff = U32(0x38);

            // The FAT's own sectors are listed by the DIFAT: 109 in the header,
            // the rest in a chain of DIFAT sectors.
            var fatSectors = new List<uint>();
            var fatCount = U32(0x2C);
            for (var i = 0; i < 109 && fatSectors.Count < fatCount; i++) { fatSectors.Add(U32(0x4C + (i * 4))); }

            var difat = U32(0x44);
            var perDifat = (_sectorSize / 4) - 1;
            var difatSeen = new HashSet<uint>();
            while (difat < EndOfChain - 2 && fatSectors.Count < fatCount)
            {
                if (!difatSeen.Add(difat)) { throw new InvalidDataException("the sector list loops"); }
                var at = Offset(difat);
                for (var i = 0; i < perDifat && fatSectors.Count < fatCount; i++) { fatSectors.Add(U32(at + (i * 4))); }
                difat = U32(at + (perDifat * 4));
            }

            var fat = new List<uint>();
            foreach (var s in fatSectors)
            {
                var at = Offset(s);
                for (var i = 0; i < _sectorSize / 4; i++) { fat.Add(U32(at + (i * 4))); }
            }

            _fat = [.. fat];
            _dir = Chain(U32(0x30), ulong.MaxValue);

            var miniFatBytes = Chain(U32(0x3C), ulong.MaxValue);
            _miniFat = new uint[miniFatBytes.Length / 4];
            for (var i = 0; i < _miniFat.Length; i++) { _miniFat[i] = BinaryPrimitives.ReadUInt32LittleEndian(miniFatBytes.AsSpan(i * 4)); }

            var root = Entry(0);
            _miniStream = root.Start >= EndOfChain - 2 ? [] : Chain(root.Start, root.Size);
        }

        public DirEntry Entry(uint index)
        {
            var at = checked((int)index * EntrySize);
            if (index == NoStream || at + EntrySize > _dir.Length) { throw new InvalidDataException("a directory entry is out of range"); }

            var d = _dir.AsSpan(at, EntrySize);
            var nameLength = Math.Clamp(BinaryPrimitives.ReadUInt16LittleEndian(d[0x40..]), (ushort)0, (ushort)64);
            var name = Encoding.Unicode.GetString(d[..Math.Max(0, nameLength - 2)]);

            return new DirEntry(
                name, d[0x42],
                BinaryPrimitives.ReadUInt32LittleEndian(d[0x44..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[0x48..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[0x4C..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[0x74..]),
                _sectorSize == 512 ? BinaryPrimitives.ReadUInt32LittleEndian(d[0x78..]) : BinaryPrimitives.ReadUInt64LittleEndian(d[0x78..]));
        }

        /// <summary>The entries directly inside a storage: its child's tree, every node of it.</summary>
        public IEnumerable<uint> Children(uint storage)
        {
            var seen = new HashSet<uint>();
            var pending = new Stack<uint>();
            pending.Push(Entry(storage).Child);

            while (pending.Count > 0)
            {
                var i = pending.Pop();
                if (i == NoStream || !seen.Add(i)) { continue; }
                if (seen.Count > _dir.Length / EntrySize) { throw new InvalidDataException("the directory loops"); }

                var e = Entry(i);
                pending.Push(e.Left);
                pending.Push(e.Right);
                yield return i;
            }
        }

        public byte[] Read(DirEntry e) =>
            e.Size < _miniCutoff ? MiniChain(e.Start, e.Size) : Chain(e.Start, e.Size);

        private byte[] Chain(uint start, ulong size)
        {
            using var output = new MemoryStream();
            // A sector visited twice is a loop. Bounding only the hop count is not
            // enough: a loop shorter than the stream fills it with repeats of the
            // same sector, which can still read as a report, just a wrong one.
            var visited = new HashSet<uint>();
            for (var s = start; s < EndOfChain - 2 && (ulong)output.Length < size;)
            {
                if (!visited.Add(s)) { throw new InvalidDataException("a stream's sector chain loops"); }
                output.Write(_b, Offset(s), _sectorSize);
                s = s < _fat.Length ? _fat[s] : EndOfChain;
            }

            return Trim(output, size);
        }

        private byte[] MiniChain(uint start, ulong size)
        {
            using var output = new MemoryStream();
            var visited = new HashSet<uint>();
            for (var s = start; s < EndOfChain - 2 && (ulong)output.Length < size;)
            {
                var at = checked((long)s * _miniSectorSize);
                if (!visited.Add(s) || s >= _miniFat.Length || at + _miniSectorSize > _miniStream.Length)
                {
                    throw new InvalidDataException("a small stream's chain is damaged");
                }

                output.Write(_miniStream, (int)at, _miniSectorSize);
                s = _miniFat[s];
            }

            return Trim(output, size);
        }

        private static byte[] Trim(MemoryStream output, ulong size)
        {
            var bytes = output.ToArray();
            return size == ulong.MaxValue || (ulong)bytes.Length <= size ? bytes : bytes[..(int)size];
        }

        private int Offset(uint sector)
        {
            var at = (long)(sector + 1) * _sectorSize;
            if (at + _sectorSize > _b.Length) { throw new InvalidDataException("a sector lies past the end of the file"); }
            return (int)at;
        }

        private ushort U16(int at) => BinaryPrimitives.ReadUInt16LittleEndian(_b.AsSpan(at));

        private uint U32(int at) => BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan(at));
    }
}
