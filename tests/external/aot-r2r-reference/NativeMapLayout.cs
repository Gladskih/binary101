#nullable enable
using Internal.NativeFormat;

// Field grammar from NativeLayoutInfoLoadContext and GenericDictionaryCell, using upstream
// NativeParser for integer, lookback and relative offset decoding.
static class NativeMapLayout
{
    public static uint ExternalType(ref NativeParser parser)
    {
        var kind = parser.GetTypeSignatureKind(out uint data);
        if (kind == TypeSignatureKind.Lookback)
        {
            var lookback = parser.GetLookbackParser(data);
            return ExternalType(ref lookback);
        }
        if (kind != TypeSignatureKind.External) throw new InvalidDataException("Expected external type");
        return data;
    }

    public static void Type(ref NativeParser parser)
    {
        var kind = parser.GetTypeSignatureKind(out uint data);
        switch (kind)
        {
            case TypeSignatureKind.Lookback:
                var lookback = parser.GetLookbackParser(data);
                Type(ref lookback);
                break;
            case TypeSignatureKind.Variable:
            case TypeSignatureKind.BuiltIn:
            case TypeSignatureKind.External: break;
            case TypeSignatureKind.Modifier: Type(ref parser); break;
            case TypeSignatureKind.Instantiation:
                for (uint index = 0; index <= data; index++) Type(ref parser);
                break;
            case TypeSignatureKind.MultiDimArray:
                Type(ref parser);
                Integers(ref parser);
                Integers(ref parser);
                break;
            case TypeSignatureKind.FunctionPointer:
                parser.GetUnsigned();
                uint count = parser.GetSequenceCount();
                for (uint index = 0; index <= count; index++) Type(ref parser);
                break;
            default: throw new InvalidDataException("Unknown type kind");
        }
    }

    static void Integers(ref NativeParser parser)
    {
        uint count = parser.GetSequenceCount();
        for (uint index = 0; index < count; index++) parser.GetUnsigned();
    }

    public static Dictionary<string, object?> Method(ref NativeParser parser, Func<uint, long?> function)
    {
        uint signatureOffset = parser.Offset;
        uint flags = parser.GetUnsigned();
        long? entrypointRva = (flags & 4) != 0 ? function(parser.GetUnsigned()) : null;
        Type(ref parser);
        uint methodToken = parser.GetUnsigned();
        if ((flags & 1) != 0)
        {
            uint count = parser.GetSequenceCount();
            for (uint index = 0; index < count; index++) Type(ref parser);
        }
        return new() { ["signatureOffset"] = signatureOffset, ["flags"] = flags,
            ["methodToken"] = methodToken, ["entrypointRva"] = entrypointRva };
    }

    public static List<object> Dictionary(ref NativeParser parser, Func<uint, long?> function)
    {
        var methods = new List<object>();
        uint count = parser.GetSequenceCount();
        for (uint index = 0; index < count; index++)
        {
            var kind = parser.GetFixupSignatureKind();
            if (kind is FixupSignatureKind.MethodDictionary or FixupSignatureKind.MethodLdToken or FixupSignatureKind.Method)
                methods.Add(Method(ref parser, function));
            else if (kind == FixupSignatureKind.GenericConstrainedMethod)
            {
                Type(ref parser);
                methods.Add(Method(ref parser, function));
            }
            else SkipCell(ref parser, kind);
        }
        return methods;
    }

    static void SkipCell(ref NativeParser parser, FixupSignatureKind kind)
    {
        if (kind == FixupSignatureKind.NotYetSupported) { parser.GetUnsigned(); return; }
        Type(ref parser);
        if (kind is FixupSignatureKind.NonGenericInstanceConstrainedMethod or FixupSignatureKind.NonGenericStaticConstrainedMethod)
            Type(ref parser);
        if (kind is FixupSignatureKind.InterfaceCall or FixupSignatureKind.StaticData or FixupSignatureKind.FieldLdToken
            or FixupSignatureKind.NonGenericInstanceConstrainedMethod or FixupSignatureKind.NonGenericStaticConstrainedMethod)
            parser.GetUnsigned();
    }
}
