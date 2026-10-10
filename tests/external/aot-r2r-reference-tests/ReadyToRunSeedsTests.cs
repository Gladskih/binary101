using System.Reflection.PortableExecutable;

static class ReadyToRunSeedsTests
{
    public static void Run()
    {
        Test.Run("ordinary managed image machine and absent runtime functions", () =>
        {
            using var pe = new PEReader(File.OpenRead(typeof(Test).Assembly.Location));
            Test.Equal(0x14c, ReadyToRunSeeds.Machine(pe));
            Test.Equal(0, ReadyToRunSeeds.Read(pe, new byte[16], []).Length);
        });
        Test.Run("runtime function table reads first RVA", () =>
        {
            using var pe = ReadyToRunSectionFixture.OpenAssembly();
            uint metadataRva = (uint)pe.PEHeaders.CorHeader!.MetadataDirectory.RelativeVirtualAddress;
            uint[] seeds = ReadyToRunSeeds.Read(pe,
                ReadyToRunSectionFixture.Header(102, metadataRva, 8), []);
            Test.Equal(1, seeds.Length);
            // ECMA-335 metadata signature BSJB as little-endian UInt32.
            Test.Equal(0x424a5342U, seeds[0]);
        });
    }
}
