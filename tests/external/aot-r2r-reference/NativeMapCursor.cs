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
}
