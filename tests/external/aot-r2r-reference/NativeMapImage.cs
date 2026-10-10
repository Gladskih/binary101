using System.Reflection.PortableExecutable;

// Independent container mapping for oracle reads; never consumes production pointer results.
// ELF constants/layout: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
// and https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
// PE signatures/section flags: https://learn.microsoft.com/windows/win32/debug/pe-format
sealed class NativeMapImage : IDisposable
{
    record Segment(long rva, long offset, long size, long memorySize, bool executable);
    readonly FileStream file;
    readonly BinaryReader reader;
    readonly List<Segment> segments = new();
    ulong imageBase;
    public int PointerSize { get; private set; }

    public NativeMapImage(string path)
    {
        file = File.OpenRead(path);
        reader = new BinaryReader(file);
        try
        {
            if (file.Length < sizeof(uint)) throw new BadImageFormatException("Truncated image header");
            uint signature = reader.ReadUInt32();
            if ((signature & 0xffff) == 0x5a4d) ReadPe();
            else if (signature == 0x464c457f) ReadElf();
            else throw new BadImageFormatException("Expected PE or ELF image");
        }
        catch
        {
            reader.Dispose();
            file.Dispose();
            throw;
        }
    }

    void ReadPe()
    {
        file.Position = 0;
        using var pe = new PEReader(file, PEStreamOptions.LeaveOpen);
        var header = pe.PEHeaders.PEHeader ?? throw new BadImageFormatException("Missing PE header");
        imageBase = header.ImageBase;
        PointerSize = header.Magic == PEMagic.PE32 ? 4 : 8;
        foreach (var section in pe.PEHeaders.SectionHeaders)
            segments.Add(new(section.VirtualAddress, section.PointerToRawData, section.SizeOfRawData,
                Math.Max(section.VirtualSize, section.SizeOfRawData),
                ((uint)section.SectionCharacteristics & 0x20000000) != 0));
    }

    void ReadElf()
    {
        file.Position = 4;
        if (reader.ReadByte() != 2 || reader.ReadByte() != 1)
            throw new BadImageFormatException("Expected ELF64 little-endian image");
        PointerSize = 8;
        file.Position = 32;
        ulong headers = reader.ReadUInt64();
        file.Position = 54;
        ushort width = reader.ReadUInt16(), count = reader.ReadUInt16();
        ReadElfSegments(headers, width, count);
        if (segments.Count == 0) throw new BadImageFormatException("No ELF load segments");
        imageBase = checked((ulong)segments.Min(segment => segment.rva - segment.offset));
        for (int index = 0; index < segments.Count; index++)
            segments[index] = segments[index] with { rva = segments[index].rva - (long)imageBase };
    }

    void ReadElfSegments(ulong headers, int width, int count)
    {
        if (width < 56 || headers > (ulong)file.Length ||
            (ulong)count > ((ulong)file.Length - headers) / (ulong)width)
            throw new BadImageFormatException("Invalid ELF program header table");
        for (int index = 0; index < count; index++)
        {
            file.Position = checked((long)headers + width * index);
            uint type = reader.ReadUInt32(), flags = reader.ReadUInt32();
            long offset = (long)reader.ReadUInt64(), address = (long)reader.ReadUInt64();
            reader.ReadUInt64();
            long size = (long)reader.ReadUInt64(), memorySize = (long)reader.ReadUInt64();
            if (type == 1)
            {
                if (offset < 0 || size < 0 || size > file.Length - offset || memorySize < 0)
                    throw new BadImageFormatException("Invalid ELF load segment");
                segments.Add(new(address, offset, size, memorySize, (flags & 1) != 0));
            }
        }
    }

    public bool Executable(long rva) => segments.Any(segment => segment.executable &&
        rva >= segment.rva && rva - segment.rva < Math.Min(segment.size, segment.memorySize));

    public byte[] Bytes(long rva, int size)
    {
        if (size < 0) throw new ArgumentOutOfRangeException(nameof(size));
        var segment = segments.FirstOrDefault(item => rva >= item.rva && item.size >= size &&
            rva - item.rva <= item.size - size);
        if (segment == null) throw new BadImageFormatException("Image range is outside load segments");
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
        if (value == 0) return null;
        if (value < imageBase) throw new BadImageFormatException("Pointer precedes image base");
        return checked((long)(value - imageBase));
    }
    public void Dispose() { reader.Dispose(); file.Dispose(); }
}
