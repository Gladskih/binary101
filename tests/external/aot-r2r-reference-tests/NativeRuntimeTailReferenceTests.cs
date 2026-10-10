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
        Test.Run("dispatch map standard and static entries with sealed slot", () =>
        {
            using var fixture = new ElfImageFixture();
            // Tail at 0x160 points to the map at 0x180; the sealed table
            // reference at 0x164 points to 0x1c0. Relative code cell at
            // 0x1c0 resolves to executable RVA 0x1d0.
            fixture.Write32(0x160, 0x20);
            fixture.Write32(0x164, 0x5c);
            fixture.Write16(0x180, 1);
            fixture.Write16(0x184, 1);
            fixture.Write16(0x188, 2);
            fixture.Write16(0x18a, 3);
            fixture.Write16(0x18c, 0);
            fixture.Write16(0x18e, 4);
            fixture.Write16(0x190, 5);
            fixture.Write16(0x192, 0);
            fixture.Write16(0x194, 6);
            fixture.Write32(0x1c0, 0x10);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var tail = new NativeRuntimeTailReference(image, new NativeMapHydration(image, null));
            var result = JsonSerializer.SerializeToElement(tail.Read(0x140, 0x440000, 0, 0));
            var entries = result.GetProperty("dispatchMap").GetProperty("entries");
            Test.Equal(2, entries.GetArrayLength());
            Test.Equal("standard", entries[0].GetProperty("kind").GetString());
            Test.Equal("static", entries[1].GetProperty("kind").GetString());
            Test.Equal(6U, entries[1].GetProperty("contextSource").GetUInt32());
            Test.Equal(0x1d0L, result.GetProperty("sealedSlots")[0]
                .GetProperty("targetRva").GetInt64());
        });
        Test.Run("dispatch map pointer outside image", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x160, 0x100);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var tail = new NativeRuntimeTailReference(image, new NativeMapHydration(image, null));
            Test.Throws<BadImageFormatException>(() => tail.Read(0x140, 0x40000, 0, 0));
        });
    }
}
