using ILCompiler.Reflection.ReadyToRun;

// Independent offset-only traversal of R2RSignatureDecoder.ParseType/ParseMethod, v10.0.0.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunSignature.cs
// It uses the upstream NativeReader's ECMA compressed integer reader.
// Element codes follow the runtime's CorElementType, including ZapSig extensions:
// https://source.dot.net/ILCompiler.ReadyToRun/parent/parent/Common/Internal/Runtime/CorConstants.cs.html
sealed class R2RSignatureSkipper
{
    readonly NativeReader reader;
    readonly int end;
    int position;
    enum TypeTask { Type, Types, GenericArguments, ArrayShape, FunctionArguments }
    readonly record struct Pending(TypeTask Task, uint Remaining = 0);
    enum Element : byte
    {
        Void = 1, Boolean, Char, I1, U1, I2, U2, I4, U4, I8, U8, R4, R8, String,
        Ptr, ByRef, ValueType, Class, Var, Array, GenericInst, TypedByRef,
        NativeInt = 24, NativeUInt, FunctionPointer = 27, Object, SzArray, MethodVar,
        RequiredModifier, OptionalModifier, CanonZapSig = 62, ModuleZapSig,
        Sentinel = 65, Pinned = 69
    }
    static readonly HashSet<Element> primitives = [
        Element.Void, Element.Boolean, Element.Char, Element.I1, Element.U1,
        Element.I2, Element.U2, Element.I4, Element.U4, Element.I8, Element.U8,
        Element.R4, Element.R8, Element.String, Element.TypedByRef,
        Element.NativeInt, Element.NativeUInt, Element.Object, Element.CanonZapSig
    ];

    R2RSignatureSkipper(NativeReader reader, int offset, int end)
    {
        this.reader = reader;
        this.end = end;
        position = offset;
    }
    uint UInt()
    {
        if (position >= end) throw new BadImageFormatException("Truncated R2R integer");
        uint value = reader.ReadCompressedData(ref position);
        if (position > end) throw new BadImageFormatException("Truncated R2R integer");
        return value;
    }
    byte Byte()
    {
        if (position >= end) throw new BadImageFormatException("Truncated R2R signature");
        return reader.ReadByte(ref position);
    }
    void Type()
    {
        var pending = new Stack<Pending>();
        pending.Push(new(TypeTask.Type));
        while (pending.TryPop(out var task))
        {
            switch (task.Task)
            {
                case TypeTask.Type: ReadType(pending); break;
                case TypeTask.Types: ReadTypes(pending, task.Remaining); break;
                case TypeTask.GenericArguments: pending.Push(new(TypeTask.Types, UInt())); break;
                case TypeTask.ArrayShape: ReadArrayShape(); break;
                case TypeTask.FunctionArguments: ReadFunctionArguments(pending, task.Remaining); break;
            }
        }
    }
    void ReadType(Stack<Pending> pending)
    {
        Element element = (Element)(Byte() & 0x7f);
        if (primitives.Contains(element)) return;
        switch (element)
        {
            case Element.Ptr or Element.ByRef or Element.SzArray or Element.Pinned:
                pending.Push(new(TypeTask.Type)); break;
            case Element.ValueType or Element.Class or Element.Var or Element.MethodVar:
                UInt(); break;
            case Element.Array:
                pending.Push(new(TypeTask.ArrayShape)); pending.Push(new(TypeTask.Type)); break;
            case Element.GenericInst:
                pending.Push(new(TypeTask.GenericArguments)); pending.Push(new(TypeTask.Type)); break;
            case Element.FunctionPointer: ReadFunction(pending); break;
            case Element.RequiredModifier or Element.OptionalModifier or Element.ModuleZapSig:
                UInt(); pending.Push(new(TypeTask.Type)); break;
            default: throw new InvalidDataException("Unknown R2R type");
        }
    }
    static void ReadTypes(Stack<Pending> pending, uint remaining)
    {
        if (remaining == 0) return;
        pending.Push(new(TypeTask.Types, remaining - 1));
        pending.Push(new(TypeTask.Type));
    }
    void ReadArrayShape()
    {
        if (UInt() == 0) return;
        uint sizes = UInt();
        for (uint index = 0; index < sizes; index++) UInt();
        uint bounds = UInt();
        for (uint index = 0; index < bounds; index++) UInt();
    }
    void ReadFunction(Stack<Pending> pending)
    {
        if ((Byte() & 0x10) != 0) UInt();
        uint count = UInt();
        pending.Push(new(TypeTask.FunctionArguments, count));
        pending.Push(new(TypeTask.Type));
    }
    void ReadFunctionArguments(Stack<Pending> pending, uint remaining)
    {
        if (remaining == 0) return;
        while (position < end && (Element)(reader[position] & 0x7f) == Element.Sentinel) Byte();
        pending.Push(new(TypeTask.FunctionArguments, remaining - 1));
        pending.Push(new(TypeTask.Type));
    }
    public static int Method(NativeReader reader, int offset, int end)
    {
        if (offset < 0 || end < offset) throw new BadImageFormatException("Invalid R2R signature range");
        var cursor = new R2RSignatureSkipper(reader, offset, end);
        uint flags = cursor.UInt();
        if ((flags & 0x80) != 0) cursor.UInt();
        if ((flags & 0x40) != 0) cursor.Type();
        cursor.UInt();
        if ((flags & 4) != 0)
        {
            uint count = cursor.UInt();
            for (uint index = 0; index < count; index++) cursor.Type();
        }
        if ((flags & 0x20) != 0) cursor.Type();
        return cursor.position;
    }
}
