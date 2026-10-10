using System.Reflection.PortableExecutable;
using System.Buffers.Binary;
using System.Text.Json;

static class ReadyToRunImportsTests
{
    public static void Run()
    {
        Test.Run("empty import section", () =>
        {
            using var pe = new PEReader(File.OpenRead(typeof(Test).Assembly.Location));
            Test.Equal(0, ReadyToRunImports.Read(pe, []).Count);
        });
        Test.Run("truncated import descriptor", () =>
        {
            using var pe = new PEReader(File.OpenRead(typeof(Test).Assembly.Location));
            Test.Throws<BadImageFormatException>(() => ReadyToRunImports.Read(pe, [0]));
        });
        Test.Run("import descriptor reads four byte cell", () =>
        {
            using var pe = ReadyToRunSectionFixture.OpenAssembly();
            int metadataRva = pe.PEHeaders.CorHeader!.MetadataDirectory.RelativeVirtualAddress;
            byte[] descriptor = new byte[20];
            BinaryPrimitives.WriteInt32LittleEndian(descriptor, metadataRva);
            BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4), 4);
            descriptor[11] = 4;
            var row = JsonSerializer.SerializeToElement(ReadyToRunImports.Read(pe, descriptor))[0];
            var values = row.GetProperty("entries")[0].GetProperty("value");
            // ECMA-335 metadata signature is BSJB, used as a known local cell payload.
            Test.Equal(1, row.GetProperty("entries").GetArrayLength());
            Test.Equal(0x42, values[0].GetInt32());
            Test.Equal(0x53, values[1].GetInt32());
            Test.Equal(0x4a, values[2].GetInt32());
            Test.Equal(0x42, values[3].GetInt32());
        });
    }
}
