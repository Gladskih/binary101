using System.Reflection.PortableExecutable;
using ILCompiler.Reflection.ReadyToRun;

// Composite component directory and core-header offsets:
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
static class ReadyToRunComposite
{
    public static byte[] Header(PEReader pe)
    {
        var directory = pe.PEHeaders.CorHeader?.ManagedNativeHeaderDirectory;
        if (directory?.Size >= 16)
        {
            var header = ReadyToRunReference.Data(pe, (uint)directory.Value.RelativeVirtualAddress,
                (uint)directory.Value.Size);
            if (ReadyToRunReference.UInt32(header, 0) == 0x00525452) return header;
        }
        // Use the unmodified upstream PE export reader, including CLR-free images.
        if (!pe.TryGetCompositeReadyToRunHeader(out int rva)) return Array.Empty<byte>();
        var prefix = ReadyToRunReference.Data(pe, (uint)rva, 16);
        uint count = ReadyToRunReference.UInt32(prefix, 12);
        if (count > (int.MaxValue - 16) / 12)
            throw new BadImageFormatException("ReadyToRun section directory is too large");
        return ReadyToRunReference.Data(pe, (uint)rva, 16 + count * 12);
    }

    public static List<object> Components(PEReader pe, byte[] header, SortedSet<uint> indices)
    {
        var components = new List<object>();
        uint count = ReadyToRunReference.UInt32(header, 12);
        if (count > (header.Length - 16) / 12)
            throw new BadImageFormatException("Truncated composite section directory");
        for (int index = 0; index < count; index++)
        {
            int directory = 16 + index * 12;
            if (ReadyToRunReference.UInt32(header, directory) != 115) continue;
            var table = ReadyToRunReference.Data(pe, ReadyToRunReference.UInt32(header, directory + 4),
                ReadyToRunReference.UInt32(header, directory + 8));
            if (table.Length % 16 != 0)
                throw new BadImageFormatException("Truncated composite component row");
            for (int offset = 0; offset < table.Length; offset += 16)
            {
                var core = ReadyToRunReference.Data(pe, ReadyToRunReference.UInt32(table, offset + 8),
                    ReadyToRunReference.UInt32(table, offset + 12));
                if (core.Length < 8)
                    throw new BadImageFormatException("Truncated composite core header");
                components.Add(new
                {
                    flags = ReadyToRunReference.UInt32(core, 0),
                    sectionCount = ReadyToRunReference.UInt32(core, 4),
                    sections = ReadyToRunReference.Sections(pe, core, indices, 8, 4,
                        System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4)))
                });
            }
        }
        return components;
    }
}
