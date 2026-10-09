#nullable enable
using Internal.Runtime;

// The reference corpus uses NativeAOT header 16.0; layout follows the v10 runtime.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
sealed class NativeRuntimeTailReference(NativeMapImage image, NativeMapHydration hydration)
{
    sealed record Dispatch(long rva, uint[] counts, List<Dictionary<string, object>> entries);
    readonly Dictionary<long, Dispatch> maps = new();

    Dispatch Map(long address)
    {
        if (maps.TryGetValue(address, out var cached)) return cached;
        uint[] counts = Enumerable.Range(0, 4).Select(index => hydration.Unsigned(address + index * 2, 2)).ToArray();
        var entries = new List<Dictionary<string, object>>();
        string[] kinds = ["standard", "default", "static", "default static"];
        long cursor = address + 8;
        for (int group = 0; group < 4; group++)
            for (int index = 0; index < counts[group]; index++)
            {
                var entry = new Dictionary<string, object> { ["kind"] = kinds[group],
                    ["interfaceIndex"] = hydration.Unsigned(cursor, 2),
                    ["interfaceMethodSlot"] = hydration.Unsigned(cursor + 2, 2),
                    ["implementationSlot"] = hydration.Unsigned(cursor + 4, 2) };
                if (group >= 2) entry["contextSource"] = hydration.Unsigned(cursor + 6, 2);
                cursor += group >= 2 ? 8 : 6;
                entries.Add(entry);
            }
        var result = new Dispatch(address, counts, entries);
        maps.Add(address, result);
        return result;
    }

    long Code(long target)
    {
        if (!image.Executable(target)) throw new InvalidDataException("Runtime type code target is not executable");
        return target;
    }

    List<object> Sealed(long address, uint flags, uint numVtableSlots, Dispatch? dispatch)
    {
        var result = new List<object>();
        if ((flags & 0x400000) == 0) return result;
        long table = hydration.Relative(address);
        var referenced = dispatch?.entries.Select(entry => (uint)entry["implementationSlot"])
            .Where(slot => slot >= numVtableSlots && slot < SpecialDispatchMapSlot.Diamond)
            .Select(slot => slot - numVtableSlots).Distinct() ?? [];
        foreach (uint slot in referenced)
        {
            long target = hydration.Relative(table + slot * 4);
            bool requiresInstantiatingThunk = (flags >> 26 & 31) == 21
                && (target & DispatchMapCodePointerFlags.RequiresInstantiatingThunkFlag) != 0;
            long targetRva = Code(requiresInstantiatingThunk ?
                target - DispatchMapCodePointerFlags.RequiresInstantiatingThunkFlag : target);
            result.Add(new { slot, targetRva, requiresInstantiatingThunk });
        }
        return result;
    }

    public object Read(long rva, uint flags, uint numVtableSlots, uint numInterfaces)
    {
        long cursor = rva + 16 + image.PointerSize * (1 + numVtableSlots + numInterfaces) + 8;
        Dispatch? dispatch = null;
        if ((flags & 0x40000) != 0) { dispatch = Map(hydration.Relative(cursor)); cursor += 4; }
        long? finalizerRva = null;
        if ((flags & 0x100000) != 0) { finalizerRva = Code(hydration.Relative(cursor)); cursor += 4; }
        return new { finalizerRva, dispatchMap = dispatch, sealedSlots = Sealed(cursor, flags, numVtableSlots, dispatch) };
    }
}
