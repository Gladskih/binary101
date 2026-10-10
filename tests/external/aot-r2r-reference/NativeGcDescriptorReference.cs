#nullable enable

// Developer oracle for gcdesc.h / GCDescEncoder.cs in dotnet/runtime v9.0.0 and v10.0.0.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gc/gcdesc.h
// This deliberately reads backwards with C# native-word arithmetic, independently of the TS parser.
sealed class NativeGcDescriptorReference(NativeMapImage image, NativeMapHydration hydration)
{
    ulong Word(long address) => hydration.Unsigned(address, 4) |
        (image.PointerSize == 8 ? (ulong)hydration.Unsigned(address + 4, 4) << 32 : 0);

    long Signed(long address) => image.PointerSize == 8 ? unchecked((long)Word(address)) :
        unchecked((int)Word(address));

    public object? Read(long rva, uint flags, uint baseSize, uint numVtableSlots)
    {
        // RuntimeAugments.EnsureMethodTableSafeToAllocate: necessary types have no GCDesc.
        if ((flags & 0x01000000) == 0 || numVtableSlots == 0) return null;
        int width = image.PointerSize;
        long count = Signed(rva - width);
        if (count == 0 || count > rva / width || count < -rva / width)
            throw new InvalidDataException("Invalid GC series count");
        uint element = (flags >> 26) & 31;
        if (element is 0x17 or 0x18)
        {
            ulong first = Word(rva - 2 * width);
            if (count > 0)
            {
                if (count != 1 || Signed(rva - 3 * width) != -(long)baseSize || first != (ulong)(baseSize - width))
                    throw new InvalidDataException("Invalid reference-array GCDesc");
                return new { kind = "array-all-references", dataOffset = first };
            }
            var repeating = new List<object>();
            for (long index = 0; index < -count; index++)
            {
                ulong packed = Word(rva - (3 + index) * width);
                repeating.Add(new { pointerCount = packed & (width == 8 ? uint.MaxValue : ushort.MaxValue),
                    skipBytes = packed >> (width * 4) });
            }
            return new { kind = "array-repeating", firstReferenceOffset = first, series = repeating };
        }
        if (count < 0) throw new InvalidDataException("Negative object GCDesc count");
        var series = new List<object>();
        for (long index = 0; index < count; index++)
            series.Add(new { offset = Word(rva - (2 + 2 * index) * width),
                bytes = Signed(rva - (3 + 2 * index) * width) + baseSize });
        return new { kind = "object", series };
    }
}
