using ILCompiler.Reflection.ReadyToRun;

static class NativeMapCursorTests
{
    static NativeMapCursor Cursor(params byte[] bytes) =>
        new(new NativeReader(new MemoryStream(bytes)), 0);

    public static void Run()
    {
        Test.Run("map cursor scalar and text fields", () =>
        {
            var cursor = Cursor(0x54, 0x78, 0x56, 0x34, 0x12, 0x0a, 0x04, 0x68, 0x69);
            Test.Equal(42U, cursor.UInt());
            Test.Equal(0x12345678U, cursor.FixedUInt());
            Test.Equal(5, cursor.Signed());
            Test.Equal("hi", cursor.Text());
            Test.Equal(9, cursor.Position);
        });
        Test.Run("map cursor index collection", () =>
        {
            var indices = Cursor(0x04, 0x06, 0x08).Indices();
            Test.Equal(2, indices.Length);
            Test.Equal(3U, indices[0]);
            Test.Equal(4U, indices[1]);
        });
        Test.Run("truncated map cursor field", () =>
            Test.Throws<BadImageFormatException>(() => Cursor(0x03).UInt()));
        Test.Run("truncated map cursor text", () =>
            Test.Throws<ArgumentOutOfRangeException>(() => Cursor(0x04, 0x61).Text()));
    }
}
