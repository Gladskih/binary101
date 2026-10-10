using System.Text.Json;

static class NativeFormatReferenceTests
{
    public static void Run()
    {
        Test.Run("tagged scope metadata reader export", () =>
        {
            // Small v10 NativeFormat corpus from the local oracle scan: assembly
            // HelloCSharp.dll, namespace Demo, nested type, and three methods.
            string input = Path.Combine(AppContext.BaseDirectory, "tagged-scope.blob");
            string output = Path.GetTempFileName();
            try
            {
                NativeFormatReference.Export(input, output);
                using var json = JsonDocument.Parse(File.ReadAllText(output));
                var records = json.RootElement;
                Test.Equal(27, records.GetArrayLength());
                Test.Equal(56, records[0].GetProperty("type").GetInt32());
                Test.Equal(1, records[0].GetProperty("fields").GetProperty("MajorVersion").GetInt32());
                Test.Equal("HelloCSharp", records[1].GetProperty("fields").GetProperty("Value").GetString());
            }
            finally { File.Delete(output); }
        });
        Test.Run("truncated native metadata header", () =>
        {
            string input = Path.GetTempFileName(), output = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(input, [0]);
                Test.Throws<BadImageFormatException>(() => NativeFormatReference.Export(input, output));
            }
            finally { File.Delete(input); File.Delete(output); }
        });
    }
}
