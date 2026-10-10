using System.Text.Json;

static class NativeFunctionMapReferenceTests
{
    public static void Run()
    {
        Test.Run("absent function map blobs", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var reference = new NativeFunctionMapReference([], image);
            Test.Equal<object?>(null, reference.Read());
        });
        Test.Run("struct map field name and offset", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            // One NativeHashtable entry, type index 3, one field named x at +8.
            byte[] map = [0, 2, 4, 0, 2, 0x06, 0x08, 0x02, 0x78, 0x10];
            var blobs = new Dictionary<uint, NativeMapReference.Blob>
            {
                [316] = new(0x100, map)
            };
            var reference = new NativeFunctionMapReference(blobs, image);
            var result = JsonSerializer.SerializeToElement(reference.Read());
            var row = result.GetProperty("maps")[0].GetProperty("entries")[0];
            Test.Equal(3U, row.GetProperty("typeIndex").GetUInt32());
            Test.Equal("x", row.GetProperty("fields")[0].GetProperty("name").GetString());
            Test.Equal(8U, row.GetProperty("fields")[0].GetProperty("offset").GetUInt32());
        });
        Test.Run("truncated struct map entry", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            byte[] map = [0, 2, 4, 0, 2, 0x06];
            var blobs = new Dictionary<uint, NativeMapReference.Blob>
            {
                [316] = new(0x100, map)
            };
            var reference = new NativeFunctionMapReference(blobs, image);
            Test.Throws<BadImageFormatException>(() => reference.Read());
        });
    }
}
