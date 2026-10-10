using System.Text.Json;

static class NativeRuntimeTailReferenceTests
{
    public static void Run()
    {
        Test.Run("runtime type without optional tail fields", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var tail = new NativeRuntimeTailReference(image, new NativeMapHydration(image, null));
            var result = JsonSerializer.SerializeToElement(tail.Read(0x140, 0, 0, 0));
            Test.Equal(JsonValueKind.Null, result.GetProperty("finalizerRva").ValueKind);
            Test.Equal(JsonValueKind.Null, result.GetProperty("dispatchMap").ValueKind);
            Test.Equal(0, result.GetProperty("sealedSlots").GetArrayLength());
        });
        Test.Run("runtime type finalizer relative code pointer", () =>
        {
            using var fixture = new ElfImageFixture();
            // Header plus one related-type pointer and two generic pointers
            // places the optional finalizer at RVA 0x160.
            fixture.Write32(0x160, 0x20);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var tail = new NativeRuntimeTailReference(image, new NativeMapHydration(image, null));
            var result = JsonSerializer.SerializeToElement(tail.Read(0x140, 0x100000, 0, 0));
            Test.Equal(0x180L, result.GetProperty("finalizerRva").GetInt64());
        });
    }
}
