#nullable enable
using ILCompiler.Reflection.ReadyToRun;
using System.Text.Json;

static class NativeMapReference
{
    internal record Blob(long rva, byte[] bytes);
    internal static List<int> Entries(byte[] bytes)
    {
        var reader = new NativeReader(new MemoryStream(bytes));
        var table = new NativeHashtable(reader, new NativeParser(reader, 0), (uint)bytes.Length);
        var enumerator = table.EnumerateAllEntries();
        var offsets = new HashSet<int>();
        for (var parser = enumerator.GetNext(); !parser.IsNull(); parser = enumerator.GetNext())
            offsets.Add((int)parser.Offset);
        return offsets.ToList();
    }
    internal static long Fixup(Blob table, uint index)
    {
        int offset = checked((int)index * 4);
        return table.rva + offset + (int)ReadyToRunReference.UInt32(table.bytes, offset);
    }
    static object Invoke(Blob blob, Blob fixups, NativeMapAbi abi)
    {
        var reader = new NativeReader(new MemoryStream(blob.bytes));
        var entries = new List<object>();
        foreach (int offset in Entries(blob.bytes))
        {
            var cursor = new NativeMapCursor(reader, offset);
            uint flags = cursor.UInt(), metadataOffset = cursor.UInt(), declaringTypeIndex = cursor.UInt();
            var entry = new Dictionary<string, object?> { ["flags"] = flags, ["declaringTypeIndex"] = declaringTypeIndex };
            entry[abi == NativeMapAbi.DotNet9 && (flags & 4) == 0 ? "nameAndSignatureOffset" : "metadataOffset"] = metadataOffset;
            long? entrypointRva = (flags & 0x20) != 0 ? Fixup(fixups, cursor.UInt()) : null;
            long? invokeStubRva = (flags & 0x80) == 0 ? Fixup(fixups, cursor.UInt()) : null;
            var genericArgumentIndices = new List<uint>();
            if ((flags & 2) != 0)
            {
                if (abi == NativeMapAbi.DotNet9 && (flags & 0x10) != 0)
                    entry["genericMethodSignatureOffset"] = cursor.UInt();
                if (abi == NativeMapAbi.DotNet10 || (flags & 0x40) == 0)
                {
                    uint count = cursor.UInt();
                    for (uint index = 0; index < count; index++) genericArgumentIndices.Add(cursor.UInt());
                }
            }
            entry["entrypointRva"] = entrypointRva;
            entry["invokeStubRva"] = invokeStubRva;
            entry["genericArgumentIndices"] = genericArgumentIndices;
            entries.Add(entry);
        }
        return new { entries, warnings = Array.Empty<string>() };
    }
    static Dictionary<string, object?> StackRow(NativeMapCursor cursor, long rva)
    {
        byte command = cursor.Byte();
        var row = new Dictionary<string, object?> { ["command"] = command };
        if ((command & 1) != 0) row["owningTypeToken"] = cursor.FixedUInt();
        if ((command & 2) != 0) row["nameOffset"] = cursor.UInt();
        if ((command & 4) != 0) row["signatureOffset"] = cursor.UInt();
        if ((command & 8) != 0) row["genericSignature"] = new {
            signatureOffset = cursor.UInt(), argumentCollectionOffset = cursor.UInt() };
        long slot = rva + cursor.Position;
        row["methodRva"] = slot + (int)cursor.FixedUInt();
        return row;
    }
    static object StackTrace(Blob blob)
    {
        var cursor = new NativeMapCursor(new NativeReader(new MemoryStream(blob.bytes)), 0);
        uint count = cursor.FixedUInt();
        var entries = new List<object>();
        for (uint index = 0; index < count; index++) entries.Add(StackRow(cursor, blob.rva));
        return new { entries, warnings = Array.Empty<string>() };
    }
    public static void Export(string inputPath, string outputPath)
    {
        using var input = JsonDocument.Parse(File.ReadAllText(inputPath));
        var results = new List<object>();
        foreach (var item in input.RootElement.EnumerateArray())
        {
            var blobs = item.GetProperty("blobs").EnumerateArray().ToDictionary(
                blob => blob.GetProperty("type").GetUInt32(), blob => new Blob(
                    blob.GetProperty("rva").GetInt64(), Convert.FromBase64String(blob.GetProperty("data").GetString()!)));
            var result = new Dictionary<string, object?> { ["path"] = item.GetProperty("path").GetString() };
            NativeMapAbi abi = item.TryGetProperty("majorVersion", out var version) && version.GetUInt32() <= 10 ?
                NativeMapAbi.DotNet9 : NativeMapAbi.DotNet10;
            if (blobs.TryGetValue(306, out var invoke)) result["invokeMap"] = Invoke(invoke, blobs[308], abi);
            if (blobs.TryGetValue(327, out var stack)) result["stackTraceMap"] = StackTrace(stack);
            using var image = new NativeMapImage(item.GetProperty("path").GetString()!);
            result["functionMaps"] = new NativeFunctionMapReference(blobs, image, abi).Read();
            results.Add(result);
        }
        File.WriteAllText(outputPath, JsonSerializer.Serialize(results));
    }
}
