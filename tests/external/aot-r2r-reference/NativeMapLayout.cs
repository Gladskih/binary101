#nullable enable
using Internal.NativeFormat;

// Field grammar from NativeLayoutInfoLoadContext and GenericDictionaryCell, using upstream
// NativeParser for integer, lookback and relative offset decoding.
enum NativeMapAbi { DotNet9, DotNet10 }

sealed class NativeMapLayout(NativeMapAbi abi)
{
    enum Continuation { Lookback, ArrayDimensions }

    public Dictionary<string, object?> Identity(ref NativeParser parser)
    {
        if (abi == NativeMapAbi.DotNet10) return new() { ["methodToken"] = parser.GetUnsigned() };
        string name = parser.GetString();
        var signature = parser.GetParserFromRelativeOffset();
        return new() { ["methodName"] = name, ["methodSignatureOffset"] = signature.Offset };
    }
    public static uint ExternalType(ref NativeParser parser)
    {
        var current = parser;
        bool first = true;
        while (true)
        {
            uint start = current.Offset;
            var kind = current.GetTypeSignatureKind(out uint data);
            if (first) { parser = current; first = false; }
            if (kind != TypeSignatureKind.Lookback)
            {
                if (kind != TypeSignatureKind.External)
                    throw new InvalidDataException("Expected external type");
                return data;
            }
            var lookback = current.GetLookbackParser(data);
            if (lookback.Offset >= start) throw new BadImageFormatException("Invalid type lookback");
            current = lookback;
        }
    }

    public static void Type(ref NativeParser parser) =>
        parser = new NativeMapTypeTraversal(parser).Read();

    public Dictionary<string, object?> Method(ref NativeParser parser, Func<uint, long?> function)
    {
        uint signatureOffset = parser.Offset;
        uint flags = parser.GetUnsigned();
        long? entrypointRva = (flags & 4) != 0 ? function(parser.GetUnsigned()) : null;
        Type(ref parser);
        var identity = Identity(ref parser);
        if ((flags & 1) != 0)
        {
            uint count = parser.GetSequenceCount();
            for (uint index = 0; index < count; index++) Type(ref parser);
        }
        identity["signatureOffset"] = signatureOffset;
        identity["flags"] = flags;
        identity["entrypointRva"] = entrypointRva;
        return identity;
    }

    public List<object> Dictionary(ref NativeParser parser, Func<uint, long?> function)
    {
        var methods = new List<object>();
        uint count = parser.GetSequenceCount();
        for (uint index = 0; index < count; index++)
        {
            var kind = parser.GetFixupSignatureKind();
            if (abi == NativeMapAbi.DotNet9 && kind == FixupSignatureKind.FieldLdToken)
            {
                var signature = parser.GetParserFromRelativeOffset();
                Type(ref signature);
                signature.GetString();
                continue;
            }
            if (abi == NativeMapAbi.DotNet9 && kind is FixupSignatureKind.MethodLdToken or FixupSignatureKind.GenericConstrainedMethod)
            {
                if (kind == FixupSignatureKind.GenericConstrainedMethod) Type(ref parser);
                var signature = parser.GetParserFromRelativeOffset();
                methods.Add(Method(ref signature, function));
                continue;
            }
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
