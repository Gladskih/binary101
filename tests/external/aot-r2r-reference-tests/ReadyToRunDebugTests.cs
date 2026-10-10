using System.Reflection.PortableExecutable;
using System.Text.Json;

static class ReadyToRunDebugTests
{
    public static void Run()
    {
        Test.Run("empty debug info array", () =>
            Test.Equal(0, ReadyToRunDebug.Read([0], 16, Machine.Amd64).Count));
        Test.Run("packed bound keeps 33-bit IL field and ignores padding", () =>
        {
            // NativeArray one-entry leaf (0x08, 1, 0), then debug payload:
            // nibble lengths 7/0, row count 1, native width 1, IL width 33.
            // Packed little-endian fields: source=1, native delta=1,
            // IL=2^32; four high padding bits must not create another row.
            byte[] bytes = [0x08, 1, 0, 0, 0x07, 0x01, 0x0c, 0x05, 0, 0, 0, 0x08];
            var methods = JsonSerializer.SerializeToElement(
                ReadyToRunDebug.Read(bytes, 16, Machine.Amd64));
            var bounds = methods[0].GetProperty("bounds");
            Test.Equal(1, bounds.GetArrayLength());
            Test.Equal(1U, bounds[0].GetProperty("nativeOffset").GetUInt32());
            Test.Equal(4294967293L, bounds[0].GetProperty("ilOffset").GetInt64());
            Test.Equal(16, bounds[0].GetProperty("source").GetInt32());
            Test.Equal(0, methods[0].GetProperty("variables").GetArrayLength());
        });
        Test.Run("packed bound count exceeds payload bits", () =>
        {
            // Count 2, with space for only one 36-bit row.
            byte[] bytes = [0x08, 1, 0, 0, 0x07, 0x02, 0x0c, 0x05, 0, 0, 0, 0x08,
                0, 0, 0, 0, 0];
            Test.Throws<BadImageFormatException>(() =>
                ReadyToRunDebug.Read(bytes, 16, Machine.Amd64));
        });
        Test.Run("register variable location", () =>
        {
            // Nibble variable payload: one row, start 2, length 3, encoded IL
            // variable 4 maps to zero, VLT_REG=0, register 7.
            byte[] bytes = [0x08, 1, 0, 0, 0x30, 0x21, 0x43, 0x70];
            var methods = JsonSerializer.SerializeToElement(
                ReadyToRunDebug.Read(bytes, 16, Machine.Amd64));
            var variable = methods[0].GetProperty("variables")[0];
            Test.Equal(2U, variable.GetProperty("startOffset").GetUInt32());
            Test.Equal(5U, variable.GetProperty("endOffset").GetUInt32());
            Test.Equal(0, variable.GetProperty("variableNumber").GetInt32());
            Test.Equal("register", variable.GetProperty("location").GetProperty("kind").GetString());
            Test.Equal(7, variable.GetProperty("location").GetProperty("register").GetInt32());
        });
    }
}
