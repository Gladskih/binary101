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
        Test.Run("delegate map resolves three executable fixups", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            // NativeHashtable leaf at offset 5: type index 3 and three fixup indices 0.
            var blobs = new Dictionary<uint, NativeMapReference.Blob>
            {
                [317] = new(0x100, [0, 2, 4, 0, 2, 6, 0, 0, 0]),
                [308] = new(0x100, [0, 0, 0, 0])
            };
            var result = JsonSerializer.SerializeToElement(
                new NativeFunctionMapReference(blobs, image).Read());
            var row = result.GetProperty("maps")[0].GetProperty("entries")[0];
            Test.Equal(3U, row.GetProperty("typeIndex").GetUInt32());
            Test.Equal(0x100L, row.GetProperty("openStaticRva").GetInt64());
            Test.Equal(0x100L, row.GetProperty("closedRva").GetInt64());
            Test.Equal(0x100L, row.GetProperty("forwardCreationRva").GetInt64());
        });
        Test.Run("exact method map carries generic argument and entrypoint", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            // Declaring type 3, method token 5, one generic type index 2,
            // entrypoint fixup index 0.
            var blobs = new Dictionary<uint, NativeMapReference.Blob>
            {
                [336] = new(0x100, [0, 2, 4, 0, 2, 6, 10, 2, 4, 0]),
                [331] = new(0x100, [0, 0, 0, 0])
            };
            var result = JsonSerializer.SerializeToElement(
                new NativeFunctionMapReference(blobs, image).Read());
            var row = result.GetProperty("maps")[0].GetProperty("entries")[0];
            Test.Equal(3U, row.GetProperty("declaringTypeIndex").GetUInt32());
            Test.Equal(5U, row.GetProperty("methodToken").GetUInt32());
            Test.Equal(2U, row.GetProperty("genericArgumentIndices")[0].GetUInt32());
            Test.Equal(0x100L, row.GetProperty("entrypointRva").GetInt64());
        });
        Test.Run("class constructor map reads preceding executable cell", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write64(0x178, 0x1000); // image base 0xf00 + code RVA 0x100
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var blobs = new Dictionary<uint, NativeMapReference.Blob>
            {
                [310] = new(0x100, [0, 2, 4, 0, 2, 6, 0]),
                [308] = new(0x180, [0, 0, 0, 0])
            };
            var result = JsonSerializer.SerializeToElement(
                new NativeFunctionMapReference(blobs, image).Read());
            var row = result.GetProperty("maps")[0].GetProperty("entries")[0];
            Test.Equal(3U, row.GetProperty("typeIndex").GetUInt32());
            Test.Equal(0U, row.GetProperty("staticBaseIndex").GetUInt32());
            Test.Equal(0x100L, row.GetProperty("entrypointRva").GetInt64());
        });
    }
}
