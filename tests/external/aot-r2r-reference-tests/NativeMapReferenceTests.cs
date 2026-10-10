using System.Text.Json;

static class NativeMapReferenceTests
{
    static JsonDocument Export(ElfImageFixture fixture, params (uint type, long rva, byte[] bytes)[] blobs)
    {
        string input = Path.GetTempFileName(), output = Path.GetTempFileName();
        try
        {
            File.WriteAllText(input, JsonSerializer.Serialize(new[] { new {
                path = fixture.Path, majorVersion = 16,
                blobs = blobs.Select(blob => new { blob.type, blob.rva,
                    data = Convert.ToBase64String(blob.bytes) }) } }));
            NativeMapReference.Export(input, output);
            return JsonDocument.Parse(File.ReadAllText(output));
        }
        finally { File.Delete(input); File.Delete(output); }
    }

    public static void Run()
    {
        RunEntriesAndFixups();
        RunExportedMaps();
    }

    static void RunEntriesAndFixups()
    {
        Test.Run("empty native hash table", () =>
            Test.Equal(0, NativeMapReference.Entries([0, 0, 0]).Count));
        Test.Run("truncated native hash table", () =>
            Test.Throws<ArgumentOutOfRangeException>(() => NativeMapReference.Entries([0])));
        Test.Run("fixup table uses signed relative displacement", () =>
        {
            // A -4 displacement from RVA 0x100 points to RVA 0xfc.
            var table = new NativeMapReference.Blob(0x100, [0xfc, 0xff, 0xff, 0xff]);
            Test.Equal(0xfcL, NativeMapReference.Fixup(table, 0));
        });
        Test.Run("fixup index outside table", () =>
        {
            var table = new NativeMapReference.Blob(0x100, [0, 0, 0, 0]);
            Test.Throws<BadImageFormatException>(() => NativeMapReference.Fixup(table, 1));
        });
        Test.Run("fixup index multiplication overflow", () =>
        {
            var table = new NativeMapReference.Blob(0x100, []);
            Test.Throws<OverflowException>(() => NativeMapReference.Fixup(table, uint.MaxValue));
        });
    }

    static void RunExportedMaps()
    {
        Test.Run("stack trace map row with owning type", () =>
        {
            using var fixture = new ElfImageFixture();
            // One row: owning type token 0x1234 and method displacement +8.
            byte[] stack = [1, 0, 0, 0, 1, 0x34, 0x12, 0, 0, 8, 0, 0, 0];
            using var json = Export(fixture, (327, 0x100, stack));
            var row = json.RootElement[0].GetProperty("stackTraceMap")
                .GetProperty("entries")[0];
            Test.Equal(0x1234U, row.GetProperty("owningTypeToken").GetUInt32());
            Test.Equal(0x111L, row.GetProperty("methodRva").GetInt64());
        });
        Test.Run("invoke map entry uses fixup table", () =>
        {
            using var fixture = new ElfImageFixture();
            // NativeHashtable: one bucket, one entry at offset 5. Its low hash
            // byte and signed +1 jump occupy offsets 3-4.
            byte[] invoke = [0, 2, 4, 0, 2, 0, 0x0a, 0x06, 0];
            using var json = Export(fixture, (306, 0x100, invoke),
                (308, 0x180, [0, 0, 0, 0]));
            var row = json.RootElement[0].GetProperty("invokeMap")
                .GetProperty("entries")[0];
            Test.Equal(5U, row.GetProperty("metadataOffset").GetUInt32());
            Test.Equal(3U, row.GetProperty("declaringTypeIndex").GetUInt32());
            Test.Equal(0x180L, row.GetProperty("invokeStubRva").GetInt64());
        });
        Test.Run("invoke map without required fixups", () =>
        {
            using var fixture = new ElfImageFixture();
            byte[] invoke = [0, 2, 4, 0, 2, 0, 0x0a, 0x06, 0];
            Test.Throws<BadImageFormatException>(() => Export(fixture, (306, 0x100, invoke)));
        });
    }
}
