using System.Buffers.Binary;

// ELF64 little-endian header and one PT_LOAD segment, following the ELF gABI
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
sealed class ElfImageFixture : IDisposable
{
    readonly byte[] bytes = new byte[0x200];
    public string Path { get; } = System.IO.Path.GetTempFileName();

    public ElfImageFixture()
    {
        bytes[0] = 0x7f;
        bytes[1] = (byte)'E';
        bytes[2] = (byte)'L';
        bytes[3] = (byte)'F';
        bytes[4] = 2;
        bytes[5] = 1;
        Write64(32, 64); // e_phoff
        Write16(54, 56); // e_phentsize
        Write16(56, 1);  // e_phnum
        Write32(64, 1);  // PT_LOAD
        Write32(68, 5);  // PF_R | PF_X
        Write64(72, 0x100); // p_offset
        Write64(80, 0x1000); // p_vaddr, image base = 0xf00
        Write64(96, 0x100); // p_filesz
        Write64(104, 0x100); // p_memsz
        Save();
    }

    public void Write16(int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
    public void Write32(int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    public void Write64(int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);
    public void WriteBytes(int offset, byte[] value) => value.CopyTo(bytes, offset);
    public void Save() => File.WriteAllBytes(Path, bytes);
    public void Dispose() => File.Delete(Path);
}
