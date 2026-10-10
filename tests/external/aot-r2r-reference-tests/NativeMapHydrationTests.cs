static class NativeMapHydrationTests
{
    public static void Run()
    {
        RunUnhydrated();
        RunHydrated();
    }

    static void RunUnhydrated()
    {
        Test.Run("unhydrated scalar and relative pointer", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x100, 8);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image, null);
            Test.Equal(8U, hydration.Unsigned(0x100, 4));
            Test.Equal(0x108L, hydration.Relative(0x100));
            Test.Equal<long?>(null, hydration.Pointer(0x108));
        });
        Test.Run("function pointer resolves executable RVA", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image, null);
            Test.Equal<long?>(0x110L, hydration.Function(0x110));
            Test.Throws<InvalidDataException>(() => hydration.Function(0x210));
        });
        Test.Run("dehydration stream shorter than destination offset", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image, new NativeMapReference.Blob(0x100, [1]));
            Test.Throws<BadImageFormatException>(() => hydration.Unsigned(0x100, 1));
        });
        Test.Run("scalar width outside native integer range", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image, null);
            Test.Throws<ArgumentOutOfRangeException>(() => hydration.Unsigned(0x100, -1));
            Test.Throws<ArgumentOutOfRangeException>(() => hydration.Unsigned(0x100, 5));
        });
    }

    static void RunHydrated()
    {
        Test.Run("hydrated copy command overrides destination bytes", () =>
        {
            using var fixture = new ElfImageFixture();
            // DehydratedDataCommand Copy=0, payload 4 is encoded as 4 << 3.
            byte[] stream = [0x10, 0, 0, 0, 0x20, 1, 2, 3, 4];
            fixture.WriteBytes(0x170, stream);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image,
                new NativeMapReference.Blob(0x170, stream));
            Test.Equal(0x04030201U, hydration.Unsigned(0x180, 4));
        });
        Test.Run("hydrated zero-fill command", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x180, uint.MaxValue);
            fixture.Save();
            // DehydratedDataCommand ZeroFill=1, payload 4 is 1 | (4 << 3).
            byte[] stream = [0x10, 0, 0, 0, 0x21];
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image,
                new NativeMapReference.Blob(0x170, stream));
            Test.Equal(0U, hydration.Unsigned(0x180, 4));
        });
        Test.Run("truncated hydrated copy payload", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            byte[] stream = [0x10, 0, 0, 0, 0x20, 1, 2];
            var hydration = new NativeMapHydration(image,
                new NativeMapReference.Blob(0x170, stream));
            Test.Throws<EndOfStreamException>(() => hydration.Unsigned(0x180, 4));
        });
        Test.Run("fat function pointer cell", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write64(0x120, 0x1080); // image base 0xf00 + executable RVA 0x180
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var hydration = new NativeMapHydration(image, null);
            Test.Equal<long?>(0x180L, hydration.Function(0x122));
        });
    }
}
