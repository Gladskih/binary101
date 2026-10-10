using System.Numerics;

// R2R v16 producer: CompressDebugInfo::CompressBoundaries and NibbleWriter.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/debuginfostore.cpp
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/nibblestream.h
static class PackedBounds
{
    // MAX_MAPPING_VALUE is -3; source bits 01/10 encode CALL_INSTRUCTION/STACK_EMPTY.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cordebuginfo.h
    public static byte[] Encode(params (uint nativeDelta, int ilOffset, int sourceBits)[] records)
    {
        int nativeBits = Width(records.Max(row => row.nativeDelta));
        int ilBits = Width(records.Max(row => checked((uint)(row.ilOffset + 3))));
        byte[] header = Nibbles((uint)records.Length, (uint)nativeBits - 1, (uint)ilBits - 1);
        int rowBits = 2 + nativeBits + ilBits;
        BigInteger packed = 0;
        for (int index = 0; index < records.Length; index++)
        {
            var row = records[index];
            BigInteger value = row.sourceBits | ((BigInteger)row.nativeDelta << 2) |
                ((BigInteger)(row.ilOffset + 3) << (2 + nativeBits));
            packed |= value << (index * rowBits);
        }
        byte[] payload = new byte[(records.Length * rowBits + 7) / 8];
        packed.TryWriteBytes(payload, out _, isUnsigned: true);
        byte[] bounds = [.. header, .. payload];
        // NativeReader short unsigned zero is "no lookback"; variables are absent.
        return [0, .. Nibbles((uint)bounds.Length, 0), .. bounds];
    }

    static int Width(uint value) => Math.Max(1, 32 - BitOperations.LeadingZeroCount(value));

    static byte[] Nibbles(params uint[] values)
    {
        var digits = new List<byte>();
        foreach (uint value in values)
        {
            var encoded = new List<byte> { (byte)(value & 7) };
            for (uint rest = value >> 3; rest != 0; rest >>= 3)
                encoded.Insert(0, (byte)((rest & 7) | 8));
            digits.AddRange(encoded);
        }
        byte[] result = new byte[(digits.Count + 1) / 2];
        for (int index = 0; index < digits.Count; index++)
            result[index / 2] |= (byte)(digits[index] << ((index % 2) * 4));
        return result;
    }
}
