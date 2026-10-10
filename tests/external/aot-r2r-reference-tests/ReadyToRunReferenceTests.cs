using System.Reflection.PortableExecutable;
using System.Text.Json;

static class ReadyToRunReferenceTests
{
    public static void Run()
    {
        Test.Run("little-endian section field", () =>
            Test.Equal(0x12345678U, ReadyToRunReference.UInt32([0, 0x78, 0x56, 0x34, 0x12], 1)));
        Test.Run("truncated section field", () =>
            Test.Throws<BadImageFormatException>(() => ReadyToRunReference.UInt32([1, 2], 0)));
        Test.Run("section count exceeds directory bytes", () =>
        {
            using var pe = ReadyToRunSectionFixture.OpenAssembly();
            byte[] header = new byte[16];
            header[12] = 1;
            Test.Throws<BadImageFormatException>(() => ReadyToRunReference.Sections(pe, header, []));
        });
        Test.Run("section data size exceeds mapped image", () =>
        {
            using var pe = ReadyToRunSectionFixture.OpenAssembly();
            uint rva = (uint)pe.PEHeaders.CorHeader!.MetadataDirectory.RelativeVirtualAddress;
            Test.Throws<BadImageFormatException>(() => ReadyToRunReference.Data(pe, rva, uint.MaxValue));
        });
        Test.Run("header with no sections", () =>
        {
            using var pe = new PEReader(File.OpenRead(typeof(Test).Assembly.Location));
            Test.Equal(0, ReadyToRunReference.Sections(pe, new byte[16], []).Count);
        });
        Test.Run("compiler identifier section reads metadata signature", () =>
        {
            using var pe = ReadyToRunSectionFixture.OpenAssembly();
            uint metadataRva = (uint)pe.PEHeaders.CorHeader!.MetadataDirectory.RelativeVirtualAddress;
            var sections = ReadyToRunReference.Sections(pe,
                ReadyToRunSectionFixture.Header(100, metadataRva, 4), []);
            var row = JsonSerializer.SerializeToElement(sections)[0];
            // ECMA-335 II.24.2.1 metadata signature bytes are BSJB.
            Test.Equal("BSJB", row.GetProperty("text").GetString());
        });
    }
}
