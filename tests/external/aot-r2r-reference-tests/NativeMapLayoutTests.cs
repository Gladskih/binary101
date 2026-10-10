using Internal.NativeFormat;

static class NativeMapLayoutTests
{
    static unsafe T Parse<T>(byte[] bytes, Func<NativeParser, T> parse)
    {
        fixed (byte* pointer = bytes)
            return parse(new NativeParser(new NativeReader(pointer, (uint)bytes.Length), 0));
    }

    public static void Run()
    {
        Test.Run("external type signature index", () =>
        {
            // NativeLayout TypeSignatureKind.External is 6, data is shifted left four.
            // NativeFormat one-byte unsigned 0x36 is encoded as 0x6c.
            uint index = Parse([0x6c], (NativeParser parser) =>
                NativeMapLayout.ExternalType(ref parser));
            Test.Equal(3U, index);
        });
        Test.Run("non-external type rejected", () =>
            Test.Throws<InvalidDataException>(() => Parse([0x0a], (NativeParser parser) =>
                NativeMapLayout.ExternalType(ref parser))));
        Test.Run("v10 method identity and function fixup", () =>
        {
            // flags=4, function index=1, external declaring type=3, method token=42.
            var result = Parse([0x08, 0x02, 0x6c, 0x54], (NativeParser parser) =>
                new NativeMapLayout(NativeMapAbi.DotNet10).Method(ref parser, index => 0x100 + index));
            Test.Equal(42U, result["methodToken"]);
            Test.Equal(4U, result["flags"]);
            Test.Equal(0x101L, result["entrypointRva"]);
        });
        Test.Run("empty dictionary layout", () =>
        {
            var result = Parse([0], (NativeParser parser) =>
                new NativeMapLayout(NativeMapAbi.DotNet10).Dictionary(ref parser, _ => null));
            Test.Equal(0, result.Count);
        });
    }
}
