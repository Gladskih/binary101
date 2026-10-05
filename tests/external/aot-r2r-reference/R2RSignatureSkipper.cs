using ILCompiler.Reflection.ReadyToRun;

// Independent offset-only traversal of R2RSignatureDecoder.ParseType/ParseMethod, v10.0.0.
// It uses the upstream NativeReader's ECMA compressed integer reader.
sealed class R2RSignatureSkipper
{
    readonly NativeReader reader;
    int position;
    static readonly HashSet<int> primitives = new() {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22, 24, 25, 28, 62 };
    static readonly Dictionary<int, Action<R2RSignatureSkipper>> types = new() {
        [15] = cursor => cursor.Type(), [16] = cursor => cursor.Type(),
        [17] = cursor => cursor.UInt(), [18] = cursor => cursor.UInt(),
        [19] = cursor => cursor.UInt(), [20] = cursor => cursor.Array(),
        [21] = cursor => cursor.Generic(), [27] = cursor => cursor.Function(),
        [29] = cursor => cursor.Type(), [30] = cursor => cursor.UInt(),
        [31] = cursor => cursor.Modified(), [32] = cursor => cursor.Modified(),
        [63] = cursor => cursor.Modified(), [69] = cursor => cursor.Type() };

    R2RSignatureSkipper(NativeReader reader, int offset) { this.reader = reader; position = offset; }
    uint UInt() => reader.ReadCompressedData(ref position);
    byte Byte() => reader.ReadByte(ref position);
    void Type()
    {
        int element = Byte() & 0x7f;
        if (primitives.Contains(element)) return;
        if (!types.TryGetValue(element, out var parse)) throw new InvalidDataException("Unknown R2R type");
        parse(this);
    }
    void Modified() { UInt(); Type(); }
    void Generic()
    {
        Type();
        uint count = UInt();
        for (uint index = 0; index < count; index++) Type();
    }
    void Array()
    {
        Type();
        if (UInt() == 0) return;
        uint sizes = UInt();
        for (uint index = 0; index < sizes; index++) UInt();
        uint bounds = UInt();
        for (uint index = 0; index < bounds; index++) UInt();
    }
    void Function()
    {
        if ((Byte() & 0x10) != 0) UInt();
        uint count = UInt();
        Type();
        for (uint index = 0; index < count; index++)
        {
            while ((reader[position] & 0x7f) == 0x41) Byte();
            Type();
        }
    }
    public static int Method(NativeReader reader, int offset)
    {
        var cursor = new R2RSignatureSkipper(reader, offset);
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
