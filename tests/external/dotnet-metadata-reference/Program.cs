using System.Text.Json;

if (args.Length < 2) throw new ArgumentException("Usage: <output.jsonl> <file-or-directory>...");
using var output = new StreamWriter(args[0]);
var total = 0;
foreach (var root in args.Skip(1))
{
    var paths = Directory.Exists(root)
        ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(path => new[] { ".dll", ".exe", ".winmd" }.Contains(Path.GetExtension(path).ToLowerInvariant()))
        : new[] { root };
    foreach (var path in paths)
    {
        try
        {
            var metadata = MetadataReference.Read(path);
            if (metadata == null) continue;
            output.WriteLine(JsonSerializer.Serialize(metadata));
            total++;
        }
        catch (Exception error) when (error is BadImageFormatException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Skip {path}: {error.Message}");
        }
    }
}
Console.Error.WriteLine($"Export {total} assemblies to {args[0]}");
