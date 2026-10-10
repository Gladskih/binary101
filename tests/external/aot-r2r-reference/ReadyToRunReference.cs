using System.Reflection.PortableExecutable;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

// Section IDs, RTR signature, and 16-byte header / 12-byte directory rows:
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
static class ReadyToRunReference
{
    internal static uint UInt32(byte[] bytes, int offset)
    {
        if (offset < 0 || offset > bytes.Length - sizeof(uint))
            throw new BadImageFormatException("Truncated ReadyToRun field");
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    }

    internal static byte[] Data(PEReader pe, uint rva, uint size)
    {
        if (rva > int.MaxValue || size > int.MaxValue)
            throw new BadImageFormatException("ReadyToRun section address exceeds PE range");
        var block = pe.GetSectionData((int)rva);
        if (size > block.Length) throw new BadImageFormatException("Truncated ReadyToRun section");
        return block.GetContent(0, (int)size).ToArray();
    }

    static string Text(byte[] bytes)
    {
        int length = Array.IndexOf(bytes, (byte)0);
        return Encoding.UTF8.GetString(bytes, 0, length < 0 ? bytes.Length : length);
    }

    static object Section(PEReader pe, SortedSet<uint> indices, uint type, byte[] bytes,
        int majorVersion)
    {
        if (type is 100 or 116) return new { type, text = Text(bytes) };
        if (type == 103)
        {
            var methods = ReadyToRunMethods.Read(bytes);
            foreach (var method in methods) indices.Add(method.runtimeFunctionIndex);
            return new { type, methods };
        }
        if (type == 109)
        {
            var methods = ReadyToRunInstanceMethods.Read(bytes);
            foreach (var method in methods) indices.Add(method.runtimeFunctionIndex);
            return new { type, methods };
        }
        if (type == 101) return new { type, imports = ReadyToRunImports.Read(pe, bytes) };
        return new
        {
            type,
            methods = ReadyToRunDebug.Read(bytes, majorVersion, (Machine)ReadyToRunSeeds.Machine(pe))
        };
    }

    internal static List<object> Sections(PEReader pe, byte[] header, SortedSet<uint> indices,
        int start = 16, int countOffset = 12, int majorVersion = 16)
    {
        var sections = new List<object>();
        uint count = UInt32(header, countOffset);
        if (start < 0 || start > header.Length || count > (header.Length - start) / 12)
            throw new BadImageFormatException("Truncated ReadyToRun section directory");
        for (int index = 0; index < count; index++)
        {
            int offset = start + index * 12;
            uint type = UInt32(header, offset), rva = UInt32(header, offset + 4);
            if (type is not (100 or 101 or 103 or 105 or 109 or 116)) continue;
            var bytes = Data(pe, rva, UInt32(header, offset + 8));
            sections.Add(Section(pe, indices, type, bytes, majorVersion));
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
                var sections = Sections(pe, header, indices, majorVersion:
                    BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4)));
                var components = ReadyToRunComposite.Components(pe, header, indices);
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    path,
                    sections,
                    components,
                    methodRvas = ReadyToRunSeeds.Read(pe, header, indices)
                }));
                count++;
            }
        }
        Console.Error.WriteLine($"Read {count} ReadyToRun assemblies with upstream NativeArray reader");
    }
}
