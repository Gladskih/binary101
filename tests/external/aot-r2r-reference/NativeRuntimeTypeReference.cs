#nullable enable
sealed class NativeRuntimeTypeReference(NativeMapImage image, NativeMapHydration hydration)
{
    readonly Dictionary<long, object> cache = new();
    readonly NativeRuntimeTailReference tails = new(image, hydration);

    public object Read(long rva)
    {
        if (cache.TryGetValue(rva, out object? cached)) return cached;
        // MethodTable fixed layout and EETypeNode virtual-slot emission, runtime v8-v10.
        uint flags = hydration.Unsigned(rva, 4), baseSize = hydration.Unsigned(rva + 4, 4);
        uint numVtableSlots = hydration.Unsigned(rva + 8 + image.PointerSize, 2);
        uint numInterfaces = hydration.Unsigned(rva + 10 + image.PointerSize, 2);
        uint hashCode = hydration.Unsigned(rva + 12 + image.PointerSize, 4);
        var slots = new List<object>();
        for (int index = 0; index < numVtableSlots; index++)
        {
            long? target = hydration.Pointer(rva + 16 + image.PointerSize * (index + 1));
            if (target == null) slots.Add(new { kind = "null" });
            else slots.Add(new { kind = image.Executable(target.Value) ? "method" : "data", rva = target.Value });
        }
        var type = new Dictionary<string, object> { ["rva"] = rva, ["flags"] = flags,
            ["baseSize"] = baseSize, ["numVtableSlots"] = numVtableSlots,
            ["numInterfaces"] = numInterfaces, ["hashCode"] = hashCode, ["slots"] = slots };
        if ((flags & 0x540000) != 0) type["tail"] = tails.Read(rva, flags, numVtableSlots, numInterfaces);
        cache.Add(rva, type);
        return type;
    }
}
