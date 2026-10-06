using System.Reflection.PortableExecutable;

// Independent container mapping for oracle reads; never consumes production pointer results.
sealed class NativeMapImage : IDisposable
{
    record Segment(long rva, long offset, long size, long memorySize, bool executable);
    readonly FileStream file;
    readonly BinaryReader reader;
    readonly List<Segment> segments = new();
    readonly ulong imageBase;
    public int PointerSize { get; }

    public NativeMapImage(string path)
    {
        file = File.OpenRead(path);
        reader = new BinaryReader(file);
        if (reader.ReadUInt16() == 0x5a4d)
        {
            file.Position = 0;
            using var pe = new PEReader(file, PEStreamOptions.LeaveOpen);
            imageBase = pe.PEHeaders.PEHeader!.ImageBase;
            PointerSize = pe.PEHeaders.PEHeader.Magic == PEMagic.PE32 ? 4 : 8;
            foreach (var section in pe.PEHeaders.SectionHeaders)
                segments.Add(new(section.VirtualAddress, section.PointerToRawData, section.SizeOfRawData,
                    Math.Max(section.VirtualSize, section.SizeOfRawData),
                    ((uint)section.SectionCharacteristics & 0x20000000) != 0));
        }
        else
        {
            file.Position = 4;
            if (reader.ReadByte() != 2 || reader.ReadByte() != 1) throw new InvalidDataException("Expected ELF64 LE");
            PointerSize = 8;
            file.Position = 32;
            ulong headers = reader.ReadUInt64();
            file.Position = 54;
            ushort width = reader.ReadUInt16(), count = reader.ReadUInt16();
            ReadElfSegments(headers, width, count);
            imageBase = (ulong)segments.Min(segment => segment.rva - segment.offset);
            for (int index = 0; index < segments.Count; index++)
                segments[index] = segments[index] with { rva = segments[index].rva - (long)imageBase };
        }
    }

    void ReadElfSegments(ulong headers, int width, int count)
    {
        for (int index = 0; index < count; index++)
        {
            file.Position = checked((long)headers + width * index);
            uint type = reader.ReadUInt32(), flags = reader.ReadUInt32();
            long offset = (long)reader.ReadUInt64(), address = (long)reader.ReadUInt64();
            reader.ReadUInt64();
            long size = (long)reader.ReadUInt64(), memorySize = (long)reader.ReadUInt64();
            if (type == 1) segments.Add(new(address, offset, size, memorySize, (flags & 1) != 0));
        }
    }

    public bool Executable(long rva) => segments.Any(segment => segment.executable &&
        rva >= segment.rva && rva < segment.rva + Math.Min(segment.size, segment.memorySize));

    public byte[] Bytes(long rva, int size)
    {
        var segment = segments.First(item => rva >= item.rva && rva + size <= item.rva + item.size);
        file.Position = segment.offset + rva - segment.rva;
        var bytes = reader.ReadBytes(size);
        if (bytes.Length != size) throw new EndOfStreamException();
        return bytes;
    }

    public long Relative(long slot) => slot + BitConverter.ToInt32(Bytes(slot, 4));
    public long? Absolute(long slot)
    {
        var bytes = Bytes(slot, PointerSize);
        ulong value = PointerSize == 8 ? BitConverter.ToUInt64(bytes) : BitConverter.ToUInt32(bytes);
        return value == 0 ? null : checked((long)(value - imageBase));
    }
    public void Dispose() { reader.Dispose(); file.Dispose(); }
}
