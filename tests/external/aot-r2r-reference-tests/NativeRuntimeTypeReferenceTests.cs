static class NativeRuntimeTypeReferenceTests
{
    public static void Run()
    {
        Test.Run("runtime type fixed fields and cache", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x140, 0);
            fixture.Write32(0x144, 24);
            fixture.Write32(0x154, 0x12345678);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            var runtime = new NativeRuntimeTypeReference(image, new NativeMapHydration(image, null));
            var result = (Dictionary<string, object>)runtime.Read(0x140);
            Test.Equal(24U, result["baseSize"]);
            Test.Equal(0x12345678U, result["hashCode"]);
            Test.Equal(0, ((List<object>)result["slots"]).Count);
            Test.Equal(true, ReferenceEquals(result, runtime.Read(0x140)));
        });
    }
}
