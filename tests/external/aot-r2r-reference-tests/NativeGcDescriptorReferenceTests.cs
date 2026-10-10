static class NativeGcDescriptorReferenceTests
{
    public static void Run()
    {
        Test.Run("type without GC pointers has no descriptor", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var gc = new NativeGcDescriptorReference(image, new NativeMapHydration(image, null));
            Test.Equal<object?>(null, gc.Read(0x140, 0, 24, 1));
        });
        Test.Run("object GC descriptor series", () =>
        {
            using var fixture = new ElfImageFixture();
            // gcdesc.h stores count one word before the type, then offset and
            // size adjustment in the two words before that.
            fixture.Write64(0x138, 1);
            fixture.Write64(0x130, 16);
            fixture.Write64(0x128, unchecked((ulong)-16L));
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var gc = new NativeGcDescriptorReference(image, new NativeMapHydration(image, null));
            dynamic result = gc.Read(0x140, 0x01000000, 24, 1)!;
            Test.Equal("object", (string)result.kind);
            Test.Equal(1, result.series.Count);
            Test.Equal(16UL, (ulong)result.series[0].offset);
            Test.Equal(8L, (long)result.series[0].bytes);
        });
        Test.Run("zero GC series count rejected", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var gc = new NativeGcDescriptorReference(image, new NativeMapHydration(image, null));
            Test.Throws<InvalidDataException>(() => gc.Read(0x140, 0x01000000, 24, 1));
        });
        Test.Run("reference array descriptor", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write64(0x138, 1);
            fixture.Write64(0x130, 16); // base size 24 less pointer size 8
            fixture.Write64(0x128, unchecked((ulong)-24L));
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var gc = new NativeGcDescriptorReference(image, new NativeMapHydration(image, null));
            var result = System.Text.Json.JsonSerializer.SerializeToElement(
                gc.Read(0x140, 0x5d000000, 24, 1));
            // HasPointers plus CorElementType SZARRAY (0x17) at flags bits 26-30.
            Test.Equal("array-all-references", result.GetProperty("kind").GetString());
            Test.Equal(16UL, result.GetProperty("dataOffset").GetUInt64());
        });
    }
}
