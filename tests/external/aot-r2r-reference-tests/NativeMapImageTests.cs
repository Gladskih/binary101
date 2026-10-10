static class NativeMapImageTests
{
    public static void Run()
    {
        Test.Run("ELF mapped bytes and executable range", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x100, 0x12345678);
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            Test.Equal(8, image.PointerSize);
            Test.Equal(true, image.Executable(0x100));
            Test.Equal(false, image.Executable(0x200));
            Test.Equal(0x78, image.Bytes(0x100, 1)[0]);
        });
        Test.Run("ELF relative and absolute targets", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0x100, 8);
            fixture.Write64(0x108, 0x1010); // image base 0xf00 plus RVA 0x110
            fixture.Save();
            using var image = new NativeMapImage(fixture.Path);
            Test.Equal(0x108L, image.Relative(0x100));
            Test.Equal<long?>(0x110L, image.Absolute(0x108));
            Test.Equal<long?>(null, image.Absolute(0x118));
        });
        Test.Run("ELF read past segment", () =>
        {
            using var fixture = new ElfImageFixture();
            using var image = new NativeMapImage(fixture.Path);
            Test.Throws<BadImageFormatException>(() => image.Bytes(0x1ff, 2));
            Test.Throws<ArgumentOutOfRangeException>(() => image.Bytes(0x100, -1));
        });
        Test.Run("invalid ELF magic", () =>
        {
            using var fixture = new ElfImageFixture();
            fixture.Write32(0, 0);
            fixture.Save();
            Test.Throws<BadImageFormatException>(() => new NativeMapImage(fixture.Path));
        });
    }
}
