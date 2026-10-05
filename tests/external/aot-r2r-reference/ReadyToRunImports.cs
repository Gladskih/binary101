using System.Reflection.PortableExecutable;
using System.Buffers.Binary;
using static ReadyToRunReference;

static class ReadyToRunImports
{
    static int PointerSize(PEReader pe)
    {
        // ReadyToRunReader reads the target Machine, including pedecoder.h OS XOR values.
        var machine = (int)pe.PEHeaders.CoffHeader.Machine;
        int[] targets = [0x14c, 0x1c4, 0x8664, 0xaa64, 0x6264, 0x5064];
        foreach (int mask in new[] { 0, 0x4644, 0xadc4, 0x7b79, 0x1993, 0x1992 })
        {
            int target = machine ^ mask;
            if (targets.Contains(target)) return target == 0x14c || target == 0x1c4 ? 4 : 8;
        }
        throw new InvalidDataException("Unsupported ReadyToRun target.");
    }

    public static List<object> Read(PEReader pe, byte[] bytes)
    {
        var imports = new List<object>();
        for (int position = 0; position < bytes.Length; position += 20)
        {
            uint cellsRva = UInt32(bytes, position), cellsSize = UInt32(bytes, position + 4);
            int width = bytes[position + 11];
            int actualWidth = width == 0 ? PointerSize(pe) : width;
            uint signatures = UInt32(bytes, position + 12);
            var cells = Data(pe, cellsRva, cellsSize);
            var sigs = signatures == 0 ? null : Data(pe, signatures, cellsSize / (uint)actualWidth * 4);
            var entries = Enumerable.Range(0, cells.Length / actualWidth).Select(index => new
            {
                value = cells.AsSpan(index * actualWidth, actualWidth).ToArray().Select(value => (int)value),
                signatureRva = sigs == null ? (uint?)null : UInt32(sigs, index * 4)
            }).ToArray();
            imports.Add(new { rva = cellsRva, size = cellsSize,
                flags = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(position + 8)),
                type = bytes[position + 10], entrySize = width, signaturesRva = signatures,
                auxiliaryDataRva = UInt32(bytes, position + 16), entries });
        }
        return imports;
    }
}
