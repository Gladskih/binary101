using ILCompiler.Reflection.ReadyToRun;

static class ReadyToRunMethodsTests
{
    static NativeReader Reader(params byte[] bytes) => new(new MemoryStream(bytes));

    public static void Run()
    {
        Test.Run("empty native method array", () =>
            Test.Equal(0, ReadyToRunMethods.Read([0]).Count));
        Test.Run("method entry without fixups", () =>
        {
            // NativeFormat compressed 12 is 0x18; R2R method entry stores index << 1.
            var entry = ReadyToRunMethods.ReadAt(Reader(0x18), 0);
            Test.Equal(6U, entry.index);
            Test.Equal<int?>(null, entry.fixups);
        });
        Test.Run("method entry with adjacent fixups", () =>
        {
            // (runtime function index 5 << 2) | fixup flag 1, then NativeFormat compression.
            var entry = ReadyToRunMethods.ReadAt(Reader(0x2a), 0);
            Test.Equal(5U, entry.index);
            Test.Equal<int?>(1, entry.fixups);
        });
        Test.Run("method entry with backward fixup distance", () =>
        {
            // Low bits 3 signal a following distance. Encoded distance 1 is 0x02.
            var entry = ReadyToRunMethods.ReadAt(Reader(0x2e, 0x02), 0);
            Test.Equal(5U, entry.index);
            Test.Equal<int?>(0, entry.fixups);
        });
        Test.Run("truncated method entry", () =>
            Test.Throws<BadImageFormatException>(() => ReadyToRunMethods.ReadAt(Reader(), 0)));
        Test.Run("truncated backward distance", () =>
            Test.Throws<BadImageFormatException>(() => ReadyToRunMethods.ReadAt(Reader(0x2e), 0)));
    }
}
