using ILCompiler.Reflection.ReadyToRun;

static class R2RSignatureSkipperTests
{
    static int Skip(params byte[] bytes) => R2RSignatureSkipper.Method(
        new NativeReader(new MemoryStream([.. bytes, 0, 0, 0, 0])), 0, bytes.Length);

    public static void Run()
    {
        Test.Run("simple method signature", () => Test.Equal(2, Skip(0, 1)));
        Test.Run("generic signature and array type", () =>
        {
            // Method flag 4 adds generic arguments; ECMA element 0x1d is SZARRAY.
            Test.Equal(6, Skip(4, 1, 2, 8, 0x1d, 8));
        });
        Test.Run("multidimensional array type", () =>
            Test.Equal(8, Skip(0x20, 1, 0x14, 8, 1, 1, 5, 0)));
        Test.Run("function pointer type", () =>
            Test.Equal(7, Skip(0x20, 1, 0x1b, 0, 1, 8, 8)));
        Test.Run("generic instantiated type", () =>
            Test.Equal(7, Skip(0x20, 1, 0x15, 0x11, 1, 1, 8)));
        Test.Run("unknown signature element", () =>
            Test.Throws<InvalidDataException>(() => Skip(0x40, 0xff, 1)));
        Test.Run("truncated type", () =>
            Test.Throws<BadImageFormatException>(() => Skip(0x40)));
        Test.Run("truncated compressed integer ignores padding", () =>
            Test.Throws<BadImageFormatException>(() => Skip(0x80)));
        Test.Run("deep valid nested type", () => Test.Equal(1027, Skip(
            [0x20, 1, .. Enumerable.Repeat((byte)0x0f, 1024), 8])));
        Test.Run("deep truncated nested type", () =>
            Test.Throws<BadImageFormatException>(() => Skip(
                [0x20, 1, .. Enumerable.Repeat((byte)0x0f, 1024)])));
    }
}
