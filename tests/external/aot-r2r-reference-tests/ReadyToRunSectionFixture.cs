using System.Buffers.Binary;
using System.Reflection.PortableExecutable;

static class ReadyToRunSectionFixture
{
    public static PEReader OpenAssembly() =>
        new(File.OpenRead(typeof(Test).Assembly.Location));

    public static byte[] Header(uint type, uint rva, uint size)
    {
        // ReadyToRun header has a 16-byte prefix followed by 12-byte section rows.
        // See dotnet/runtime ReadyToRunConstants.cs and ReadyToRunReader.cs.
        byte[] bytes = new byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16), type);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), rva);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(24), size);
        return bytes;
    }
}
