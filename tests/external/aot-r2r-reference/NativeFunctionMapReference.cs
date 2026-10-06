#nullable enable
using ILCompiler.Reflection.ReadyToRun;
using Blob = NativeMapReference.Blob;

sealed class NativeFunctionMapReference
{
    readonly Dictionary<uint, Blob> blobs;
    readonly NativeMapImage image;
    readonly NativeMapHydration hydration;
    readonly NativeRuntimeTypeReference runtimeTypes;
    readonly Dictionary<uint, object> layouts = new();

    public NativeFunctionMapReference(Dictionary<uint, Blob> blobs, NativeMapImage image)
    {
        this.blobs = blobs;
        this.image = image;
        blobs.TryGetValue(207, out var dehydrated);
        hydration = new(image, dehydrated);
        runtimeTypes = new(image, hydration);
    }
    long? Function(uint table, uint index) => hydration.Function(NativeMapReference.Fixup(blobs[table], index));

    object Struct(NativeMapCursor cursor)
    {
        uint typeIndex = cursor.UInt(), header = cursor.UInt();
        var entry = new Dictionary<string, object?> { ["typeIndex"] = typeIndex, ["header"] = header,
            ["marshalRva"] = null, ["unmarshalRva"] = null, ["cleanupRva"] = null };
        var fields = new List<object>();
        if ((header & 2) == 0)
        {
            if ((header & 1) != 0)
            {
                entry["nativeSize"] = cursor.UInt();
                entry["marshalRva"] = Function(308, cursor.UInt());
                entry["unmarshalRva"] = Function(308, cursor.UInt());
                entry["cleanupRva"] = Function(308, cursor.UInt());
            }
            for (uint index = 0; index < header >> 2; index++)
                fields.Add(new { name = cursor.Text(), offset = cursor.UInt() });
        }
        entry["fields"] = fields;
        return entry;
    }

    object Delegate(NativeMapCursor cursor)
    {
        uint typeIndex = cursor.UInt();
        return new { typeIndex, openStaticRva = Function(308, cursor.UInt()),
            closedRva = Function(308, cursor.UInt()), forwardCreationRva = Function(308, cursor.UInt()) };
    }

    object Exact(NativeMapCursor cursor)
    {
        uint declaringTypeIndex = cursor.UInt(), methodToken = cursor.UInt();
        var genericArgumentIndices = cursor.Indices();
        return new { declaringTypeIndex, methodToken, genericArgumentIndices,
            entrypointRva = Function(331, cursor.UInt()) };
    }

    object Cctor(NativeMapCursor cursor)
    {
        uint typeIndex = cursor.UInt(), staticBaseIndex = cursor.UInt();
        long baseRva = NativeMapReference.Fixup(blobs[308], staticBaseIndex);
        return new { typeIndex, staticBaseIndex,
            entrypointRva = hydration.Function(hydration.Pointer(baseRva - image.PointerSize)) };
    }

    unsafe object Layout(uint offset)
    {
        if (layouts.TryGetValue(offset, out var cached)) return cached;
        var bytes = blobs[330].bytes;
        long? classConstructorRva = null;
        var dictionaryMethods = new List<object>();
        fixed (byte* data = bytes)
        {
            var parser = new Internal.NativeFormat.NativeParser(
                new Internal.NativeFormat.NativeReader(data, (uint)bytes.Length), offset);
            for (var kind = parser.GetBagElementKind(); kind != Internal.NativeFormat.BagElementKind.End;
                kind = parser.GetBagElementKind())
            {
                if (kind == Internal.NativeFormat.BagElementKind.ClassConstructorPointer)
                    classConstructorRva = Function(333, parser.GetUnsigned());
                else if (kind == Internal.NativeFormat.BagElementKind.DictionaryLayout)
                {
                    var dictionary = parser.GetParserFromRelativeOffset();
                    dictionaryMethods = NativeMapLayout.Dictionary(ref dictionary, index => Function(331, index));
                }
                else parser.SkipInteger();
            }
        }
        var result = new { classConstructorRva, dictionaryMethods };
        layouts.Add(offset, result);
        return result;
    }

    unsafe object Template(NativeMapCursor cursor)
    {
        uint signatureOffset = cursor.UInt(), layoutOffset = cursor.UInt();
        var bytes = blobs[330].bytes;
        fixed (byte* data = bytes)
        {
            var parser = new Internal.NativeFormat.NativeParser(
                new Internal.NativeFormat.NativeReader(data, (uint)bytes.Length), signatureOffset);
            uint flags = parser.GetUnsigned();
            long? entrypointRva = (flags & 4) != 0 ? Function(331, parser.GetUnsigned()) : null;
            uint declaringTypeIndex = NativeMapLayout.ExternalType(ref parser), methodToken = parser.GetUnsigned();
            var genericArgumentIndices = new List<uint>();
            if ((flags & 1) != 0)
            {
                uint count = parser.GetSequenceCount();
                for (uint index = 0; index < count; index++) genericArgumentIndices.Add(NativeMapLayout.ExternalType(ref parser));
            }
            return new { signatureOffset, layoutOffset, flags, declaringTypeIndex, methodToken,
                genericArgumentIndices, entrypointRva, layout = Layout(layoutOffset) };
        }
    }

    object TypeTemplate(NativeMapCursor cursor)
    {
        uint typeIndex = cursor.UInt(), layoutOffset = cursor.UInt();
        return new { typeIndex, layoutOffset, layout = Layout(layoutOffset) };
    }

    object Entry(uint type, NativeMapCursor cursor) => type switch
    {
        301 => TypeMetadata(cursor),
        310 => Cctor(cursor), 316 => Struct(cursor), 317 => Delegate(cursor), 322 => Template(cursor),
        321 => TypeTemplate(cursor),
        336 => Exact(cursor), _ => throw new InvalidDataException()
    };

    object TypeMetadata(NativeMapCursor cursor)
    {
        uint typeIndex = cursor.UInt(), metadataHandle = cursor.UInt();
        return new { typeIndex, metadataHandle,
            runtimeType = runtimeTypes.Read(NativeMapReference.Fixup(blobs[308], typeIndex)) };
    }

    public object? Read()
    {
        var maps = new List<object>();
        foreach (uint type in new uint[] { 301, 310, 316, 317, 321, 322, 336 })
        {
            if (!blobs.TryGetValue(type, out var blob)) continue;
            var reader = new NativeReader(new MemoryStream(blob.bytes));
            var entries = NativeMapReference.Entries(blob.bytes).Select(offset => Entry(type,
                new NativeMapCursor(reader, offset))).ToArray();
            maps.Add(new { type, entries, warnings = Array.Empty<string>() });
        }
        return maps.Count == 0 ? null : new { maps, warnings = Array.Empty<string>() };
    }
}
