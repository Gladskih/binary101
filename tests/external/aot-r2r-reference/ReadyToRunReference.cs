using System.Reflection.PortableExecutable;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

static class ReadyToRunReference
{
    internal static uint UInt32(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));

    internal static byte[] Data(PEReader pe, uint rva, uint size) =>
        pe.GetSectionData((int)rva).GetContent(0, (int)size).ToArray();

    static string Text(byte[] bytes)
    {
        int length = Array.IndexOf(bytes, (byte)0);
        return Encoding.UTF8.GetString(bytes, 0, length < 0 ? bytes.Length : length);
    }

    internal static List<object> Sections(PEReader pe, byte[] header, SortedSet<uint> indices,
        int start = 16, int countOffset = 12)
    {
        var sections = new List<object>();
        for (int index = 0; index < UInt32(header, countOffset); index++)
        {
            int offset = start + index * 12;
            uint type = UInt32(header, offset), rva = UInt32(header, offset + 4);
            if (type is not (100 or 101 or 103 or 109 or 116)) continue;
            var bytes = Data(pe, rva, UInt32(header, offset + 8));
            if (type == 100 || type == 116) sections.Add(new { type, text = Text(bytes) });
            else if (type == 103)
            {
                var methods = ReadyToRunMethods.Read(bytes);
                foreach (var method in methods) indices.Add(method.runtimeFunctionIndex);
                sections.Add(new { type, methods });
            }
            else if (type == 109)
            {
                var methods = ReadyToRunInstanceMethods.Read(bytes);
                foreach (var method in methods) indices.Add(method.runtimeFunctionIndex);
                sections.Add(new { type, methods });
            }
            else if (type == 101) sections.Add(new { type, imports = ReadyToRunImports.Read(pe, bytes) });
        }
        return sections;
    }

    public static void Export(string outputPath, IEnumerable<string> roots)
    {
        using var output = new StreamWriter(outputPath);
        int count = 0;
        foreach (var root in roots)
        {
            var paths = Directory.Exists(root) ? Directory.EnumerateFiles(root, "*.dll",
                SearchOption.AllDirectories) : new[] { root };
            foreach (var path in paths)
            {
                using var pe = new PEReader(File.OpenRead(path));
                var header = ReadyToRunComposite.Header(pe);
                if (header.Length < 16) continue;
                if (UInt32(header, 0) != 0x00525452) continue;
                var indices = new SortedSet<uint>();
                var sections = Sections(pe, header, indices);
                var components = ReadyToRunComposite.Components(pe, header, indices);
                output.WriteLine(JsonSerializer.Serialize(new { path, sections, components,
                    methodRvas = ReadyToRunSeeds.Read(pe, header, indices) }));
                count++;
            }
        }
        Console.Error.WriteLine($"Read {count} ReadyToRun assemblies with upstream NativeArray reader");
    }
}
