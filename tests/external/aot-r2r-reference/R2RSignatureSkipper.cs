using ILCompiler.Reflection.ReadyToRun;

// Independent offset-only traversal of R2RSignatureDecoder.ParseType/ParseMethod, v10.0.0.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunSignature.cs
// It uses the upstream NativeReader's ECMA compressed integer reader.
sealed class R2RSignatureSkipper
{
    readonly NativeReader reader;
    readonly int end;
    int position;
    enum TypeTask { Type, Types, GenericArguments, ArrayShape, FunctionArguments }
    readonly record struct Pending(TypeTask Task, uint Remaining = 0);
    static readonly HashSet<int> primitives = new() {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22, 24, 25, 28, 62 };

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
        int element = Byte() & 0x7f;
        if (primitives.Contains(element)) return;
        switch (element)
        {
            case 15 or 16 or 29 or 69: pending.Push(new(TypeTask.Type)); break;
            case 17 or 18 or 19 or 30: UInt(); break;
            case 20: pending.Push(new(TypeTask.ArrayShape)); pending.Push(new(TypeTask.Type)); break;
            case 21: pending.Push(new(TypeTask.GenericArguments)); pending.Push(new(TypeTask.Type)); break;
            case 27: ReadFunction(pending); break;
            case 31 or 32 or 63: UInt(); pending.Push(new(TypeTask.Type)); break;
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
        while (position < end && (reader[position] & 0x7f) == 0x41) Byte();
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
