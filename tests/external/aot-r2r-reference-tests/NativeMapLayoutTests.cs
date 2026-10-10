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
        ExternalTypeSignatureIndex();
        NonExternalTypeRejected();
        ExternalTypeLookbackPreservesCallerPosition();
        UnderflowingTypeLookbackIsRejected();
        CyclicTypeLookbackThroughModifiersIsRejected();
        DeepModifierChainConsumesFinalBuiltInType();
        InstantiationArrayAndFunctionPointerTypes();
        V10MethodIdentityAndFunctionFixup();
        EmptyDictionaryLayout();
        DictionarySkipsTypeHandleAndDecodesMethodToken();
        DictionaryTruncatedMethodSignature();
    }

    static void ExternalTypeSignatureIndex() =>
        Test.Run("external type signature index", () =>
        {
            // NativeLayout TypeSignatureKind.External is 6, data is shifted left four.
            // NativeFormat one-byte unsigned 0x36 is encoded as 0x6c.
            uint index = Parse([0x6c], (NativeParser parser) =>
                NativeMapLayout.ExternalType(ref parser));
            Test.Equal(3U, index);
        });

    static void NonExternalTypeRejected() =>
        Test.Run("non-external type rejected", () =>
            Test.Throws<InvalidDataException>(() => Parse([0x0a], (NativeParser parser) =>
                NativeMapLayout.ExternalType(ref parser))));

    static void ExternalTypeLookbackPreservesCallerPosition() =>
        Test.Run("external type lookback preserves caller position", () =>
        {
            // Lookback data 1 at offset 3 points back four bytes to offset 0.
            uint index = Parse([0x6c, 0, 0, 0x22], (NativeParser parser) =>
            {
                parser.Offset = 3;
                uint value = NativeMapLayout.ExternalType(ref parser);
                Test.Equal(4U, parser.Offset);
                return value;
            });
            Test.Equal(3U, index);
        });

    static void UnderflowingTypeLookbackIsRejected() =>
        Test.Run("underflowing type lookback is rejected", () =>
            Test.Throws<BadImageFormatException>(() => Parse([0x02], (NativeParser parser) =>
            {
                NativeMapLayout.Type(ref parser);
                return parser.Offset;
            })));

    static void CyclicTypeLookbackThroughModifiersIsRejected() =>
        Test.Run("cyclic type lookback through modifiers is rejected", () =>
            Test.Throws<BadImageFormatException>(() => Parse([0x04, 0x04, 0x02],
                (NativeParser parser) =>
                {
                    NativeMapLayout.Type(ref parser);
                    return parser.Offset;
                })));

    static void DeepModifierChainConsumesFinalBuiltInType() =>
        Test.Run("deep modifier chain consumes final built-in type", () =>
        {
            byte[] bytes = [.. Enumerable.Repeat((byte)0x04, 32768), 0x0a];
            uint offset = Parse(bytes, (NativeParser parser) =>
            {
                NativeMapLayout.Type(ref parser);
                return parser.Offset;
            });
            Test.Equal((uint)bytes.Length, offset);
        });

    static void InstantiationArrayAndFunctionPointerTypes() =>
        Test.Run("instantiation array and function pointer types", () =>
        {
            // Instantiation with one argument: multidimensional array of a
            // built-in type (both dimension lists empty), then a function
            // pointer with one built-in return type and no parameters.
            byte[] bytes = [0x26, 0x14, 0x0a, 0, 0, 0x16, 0, 0, 0x0a];
            uint offset = Parse(bytes, (NativeParser parser) =>
            {
                NativeMapLayout.Type(ref parser);
                return parser.Offset;
            });
            Test.Equal((uint)bytes.Length, offset);
        });

    static void V10MethodIdentityAndFunctionFixup() =>
        Test.Run("v10 method identity and function fixup", () =>
        {
            // flags=4, function index=1, external declaring type=3, method token=42.
            var result = Parse([0x08, 0x02, 0x6c, 0x54], (NativeParser parser) =>
                new NativeMapLayout(NativeMapAbi.DotNet10).Method(ref parser, index => 0x100 + index));
            Test.Equal(42U, result["methodToken"]);
            Test.Equal(4U, result["flags"]);
            Test.Equal(0x101L, result["entrypointRva"]);
        });

    static void EmptyDictionaryLayout() =>
        Test.Run("empty dictionary layout", () =>
        {
            var result = Parse([0], (NativeParser parser) =>
                new NativeMapLayout(NativeMapAbi.DotNet10).Dictionary(ref parser, _ => null));
            Test.Equal(0, result.Count);
        });

    static void DictionarySkipsTypeHandleAndDecodesMethodToken() =>
        Test.Run("dictionary skips type handle and decodes method token", () =>
        {
            // Sequence of two fixups: TypeHandle=1 + BuiltIn type,
            // MethodLdToken=8 + flags=0, External type 3, method token 42.
            var result = Parse([4, 2, 0x0a, 0x10, 0, 0x6c, 0x54],
                (NativeParser parser) => new NativeMapLayout(NativeMapAbi.DotNet10)
                    .Dictionary(ref parser, _ => null));
            Test.Equal(1, result.Count);
            var method = (Dictionary<string, object?>)result[0];
            Test.Equal(42U, method["methodToken"]);
        });

    static void DictionaryTruncatedMethodSignature() =>
        Test.Run("dictionary truncated method signature", () =>
            Test.Throws<BadImageFormatException>(() => Parse([2, 0x10, 0],
                (NativeParser parser) => new NativeMapLayout(NativeMapAbi.DotNet10)
                    .Dictionary(ref parser, _ => null))));
}
