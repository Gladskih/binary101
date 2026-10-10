using Internal.NativeFormat;

// Iterative traversal of the NativeParser type grammar, including lookbacks.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
sealed class NativeMapTypeTraversal(NativeParser initial)
{
    enum Continuation { Lookback, ArrayDimensions }
    readonly Stack<(NativeParser parser, ulong pending, Continuation kind, uint offset)> frames = new();
    readonly HashSet<uint> activeLookbacks = new();
    NativeParser parser = initial;
    ulong pending = 1;

    public NativeParser Read()
    {
        while (pending != 0 || frames.Count != 0)
        {
            if (pending == 0) Resume();
            else ReadType();
        }
        return parser;
    }

    void Resume()
    {
        var frame = frames.Pop();
        if (frame.kind == Continuation.Lookback)
        {
            activeLookbacks.Remove(frame.offset);
            parser = frame.parser;
        }
        else
        {
            Integers();
            Integers();
        }
        pending = frame.pending;
    }

    void ReadType()
    {
        pending--;
        uint start = parser.Offset;
        var kind = parser.GetTypeSignatureKind(out uint data);
        if (kind == TypeSignatureKind.Lookback) ReadLookback(start, data);
        else if (kind == TypeSignatureKind.MultiDimArray)
        {
            frames.Push((parser, pending, Continuation.ArrayDimensions, 0));
            pending = 1;
        }
        else pending += ChildCount(kind, data);
    }

    void ReadLookback(uint start, uint data)
    {
        var lookback = parser.GetLookbackParser(data);
        if (lookback.Offset >= start) throw new BadImageFormatException("Invalid type lookback");
        if (!activeLookbacks.Add(lookback.Offset))
            throw new BadImageFormatException("Cyclic type lookback");
        frames.Push((parser, pending, Continuation.Lookback, lookback.Offset));
        parser = lookback;
        pending = 1;
    }

    ulong ChildCount(TypeSignatureKind kind, uint data)
    {
        switch (kind)
        {
            case TypeSignatureKind.Variable:
            case TypeSignatureKind.BuiltIn:
            case TypeSignatureKind.External: return 0;
            case TypeSignatureKind.Modifier: return 1;
            case TypeSignatureKind.Instantiation: return (ulong)data + 1;
            case TypeSignatureKind.FunctionPointer:
                parser.GetUnsigned();
                return (ulong)parser.GetSequenceCount() + 1;
            default: throw new InvalidDataException("Unknown type kind");
        }
    }

    void Integers()
    {
        uint count = parser.GetSequenceCount();
        for (uint index = 0; index < count; index++) parser.GetUnsigned();
    }
}
