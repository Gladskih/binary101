using System.Reflection.PortableExecutable;

static class ReadyToRunSeeds
{
    // ReadyToRunReader.CalculateRuntimeFunctionSize / ReadyToRunMethod.ParseRuntimeFunctions.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunMethod.cs
    static ushort Machine(PEReader pe)
    {
        ushort raw = (ushort)pe.PEHeaders.CoffHeader.Machine;
        // pedecoder.h IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE; Windows has no override.
        foreach (ushort os in new ushort[] { 0, 0x4644, 0xadc4, 0x7b79, 0x1993, 0x1992 })
        {
            ushort machine = (ushort)(raw ^ os);
            if (machine is 0x14c or 0x8664 or 0x1c4 or 0xaa64 or 0x6264 or 0x5064) return machine;
        }
        throw new InvalidDataException("Unknown R2R machine");
    }

    public static uint[] Read(PEReader pe, byte[] header, SortedSet<uint> indices)
    {
        ushort machine = Machine(pe);
        int width = machine == 0x8664 ? 12 : 8;
        for (int index = 0; index < ReadyToRunReference.UInt32(header, 12); index++)
        {
            int offset = 16 + index * 12;
            if (ReadyToRunReference.UInt32(header, offset) != 102) continue;
            var table = ReadyToRunReference.Data(pe, ReadyToRunReference.UInt32(header, offset + 4),
                ReadyToRunReference.UInt32(header, offset + 8));
            return Enumerable.Range(0, table.Length / width)
                .Select(entry => ReadyToRunReference.UInt32(table, entry * width))
                .Select(rva => machine == 0x1c4 ? rva & ~1U : rva).Distinct().ToArray();
        }
        return Array.Empty<uint>();
    }
}
