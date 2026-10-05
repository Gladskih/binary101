using ILCompiler.Reflection.ReadyToRun;

static class ReadyToRunInstanceMethods
{
    public static List<ReadyToRunInstanceMethodEntry> Read(byte[] bytes)
    {
        // ReadCompressedData peeks a DWORD even for a one-byte integer. In the original
        // PE image bytes follow this section; provide that lookahead for the sliced oracle.
        var reader = new NativeReader(new MemoryStream([.. bytes, 0, 0, 0, 0]));
        var table = new NativeHashtable(reader, new NativeParser(reader, 0), (uint)bytes.Length);
        var enumerator = table.EnumerateAllEntries();
        var methods = new Dictionary<uint, ReadyToRunInstanceMethodEntry>();
        for (var parser = enumerator.GetNext(); !parser.IsNull(); parser = enumerator.GetNext())
        {
            int offset = R2RSignatureSkipper.Method(reader, (int)parser.Offset);
            var entry = ReadyToRunMethods.ReadAt(reader, offset);
            methods.TryAdd(parser.Offset, new ReadyToRunInstanceMethodEntry(parser.Offset, entry.index, entry.fixups));
        }
        return methods.Values.ToList();
    }
}

record ReadyToRunInstanceMethodEntry(uint signatureOffset, uint runtimeFunctionIndex, int? fixupOffset);
