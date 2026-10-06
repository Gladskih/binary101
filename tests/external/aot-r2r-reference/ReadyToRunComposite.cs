using System.Reflection.PortableExecutable;
using ILCompiler.Reflection.ReadyToRun;

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
        return ReadyToRunReference.Data(pe, (uint)rva, 16 + ReadyToRunReference.UInt32(prefix, 12) * 12);
    }

    public static List<object> Components(PEReader pe, byte[] header, SortedSet<uint> indices)
    {
        var components = new List<object>();
        for (int index = 0; index < ReadyToRunReference.UInt32(header, 12); index++)
        {
            int directory = 16 + index * 12;
            if (ReadyToRunReference.UInt32(header, directory) != 115) continue;
            var table = ReadyToRunReference.Data(pe, ReadyToRunReference.UInt32(header, directory + 4),
                ReadyToRunReference.UInt32(header, directory + 8));
            for (int offset = 0; offset < table.Length; offset += 16)
            {
                var core = ReadyToRunReference.Data(pe, ReadyToRunReference.UInt32(table, offset + 8),
                    ReadyToRunReference.UInt32(table, offset + 12));
                components.Add(new { flags = ReadyToRunReference.UInt32(core, 0),
                    sectionCount = ReadyToRunReference.UInt32(core, 4),
                    sections = ReadyToRunReference.Sections(pe, core, indices, 8, 4) });
            }
        }
        return components;
    }
}
