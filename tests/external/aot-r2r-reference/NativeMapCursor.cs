using ILCompiler.Reflection.ReadyToRun;

sealed class NativeMapCursor
{
    readonly NativeReader reader;
    public int Position;
    public NativeMapCursor(NativeReader reader, int offset) { this.reader = reader; Position = offset; }
    public uint UInt()
    {
        uint value = 0;
        Position = (int)reader.DecodeUnsigned((uint)Position, ref value);
        return value;
    }
    public uint FixedUInt() => reader.ReadUInt32(ref Position);
    public byte Byte() => reader.ReadByte(ref Position);
    public int Signed()
    {
        int value = 0;
        Position = (int)reader.DecodeSigned((uint)Position, ref value);
        return value;
    }
    public string Text()
    {
        var length = checked((int)UInt());
        var bytes = new byte[length];
        for (int index = 0; index < length; index++) bytes[index] = Byte();
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
    public uint[] Indices()
    {
        var values = new uint[UInt()];
        for (int index = 0; index < values.Length; index++) values[index] = UInt();
        return values;
    }
}
