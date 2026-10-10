using System.Reflection.PortableExecutable;
using System.Buffers.Binary;
using System.Text.Json;

static class ReadyToRunCompositeTests
{
    static (PEReader pe, byte[] header) Image(uint coreSize, byte[]? compilerText = null)
    {
        byte[] bytes = File.ReadAllBytes(typeof(Test).Assembly.Location);
        using var original = new PEReader(new MemoryStream(bytes));
        uint rva = (uint)original.PEHeaders.CorHeader!.MetadataDirectory.RelativeVirtualAddress;
        var section = original.PEHeaders.SectionHeaders.First(row => rva >= row.VirtualAddress &&
            rva - row.VirtualAddress + 36 + (compilerText?.Length ?? 0) <= row.SizeOfRawData);
        int offset = section.PointerToRawData + (int)rva - section.VirtualAddress;
        // Component row is 16 bytes: core-header RVA and length are at +8/+12.
        // The core header starts at +16 and stores flags and section count.
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 8), rva + 16);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 12), coreSize);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 16), 0x1234);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 20),
            compilerText == null ? 0U : 1U);
        if (compilerText != null)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 24), 100);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 28), rva + 36);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 32),
                (uint)compilerText.Length);
            compilerText.CopyTo(bytes, offset + 36);
        }
        return (new PEReader(new MemoryStream(bytes)),
            ReadyToRunSectionFixture.Header(115, rva, 16));
    }

    public static void Run()
    {
        Test.Run("ordinary managed image has no composite header", () =>
        {
            using var pe = new PEReader(File.OpenRead(typeof(Test).Assembly.Location));
            Test.Equal(0, ReadyToRunComposite.Header(pe).Length);
            Test.Equal(0, ReadyToRunComposite.Components(pe, new byte[16], []).Count);
        });
        Test.Run("component core header flags and empty section table", () =>
        {
            var fixture = Image(8);
            using var pe = fixture.pe;
            var components = JsonSerializer.SerializeToElement(
                ReadyToRunComposite.Components(pe, fixture.header, []));
            Test.Equal(1, components.GetArrayLength());
            Test.Equal(0x1234U, components[0].GetProperty("flags").GetUInt32());
            Test.Equal(0U, components[0].GetProperty("sectionCount").GetUInt32());
            Test.Equal(0, components[0].GetProperty("sections").GetArrayLength());
        });
        Test.Run("truncated component core header", () =>
        {
            var fixture = Image(4);
            using var pe = fixture.pe;
            Test.Throws<BadImageFormatException>(() =>
                ReadyToRunComposite.Components(pe, fixture.header, []));
        });
        Test.Run("component nested compiler section", () =>
        {
            var fixture = Image(20, [(byte)'R', (byte)'2', (byte)'R', (byte)'!']);
            using var pe = fixture.pe;
            var components = JsonSerializer.SerializeToElement(
                ReadyToRunComposite.Components(pe, fixture.header, []));
            var component = components[0];
            Test.Equal(1U, component.GetProperty("sectionCount").GetUInt32());
            Test.Equal("R2R!", component.GetProperty("sections")[0]
                .GetProperty("text").GetString());
        });
    }
}
