using System.Collections;
using System.Collections.Immutable;
using System.IO.Compression;
using System.Numerics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis.Emit;

// The EnC oracle calls the installed SDK's unchanged Roslyn decoder. Other records
// use System.Reflection.Metadata BlobReader, UTF8, JSON and Deflate implementations.
static class CustomRecords {
    public static string[] Kinds() => typeof(EditAndContinueMethodDebugInformation).Assembly
        .GetType("Microsoft.CodeAnalysis.Debugging.PortableCustomDebugInfoKinds")!
        .GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
        .Where(field => field.FieldType == typeof(Guid))
        .Select(field => ((Guid)field.GetValue(null)!).ToString()).Order().ToArray();

    public static object? Decode(Guid kind, BlobReader reader) {
        var bytes = reader.ReadBytes(reader.RemainingBytes);
        var id = kind.ToString();
        if (id == "755f52a8-91c5-45be-b4b8-209571e552bd" ||
            id == "a643004c-0240-496f-a783-30d64f4979de" ||
            id == "8b78cd68-2ede-420b-980b-e15884b8aaa3") return Enc(id, bytes);
        reader.Reset();
        return id switch {
            "cc110556-a091-4d38-9fec-25ab9a351a6a" => SourceLink(bytes),
            "0e8a571b-6926-466e-b4ad-8ab04611f5fe" => Source(bytes),
            "b5feec05-8cd0-4a83-96da-466284bb4bd8" => Options(reader),
            "7e4d4708-096e-4c5c-aeda-cb10ba6a740d" => References(reader),
            "54fd2ac5-e925-401a-9c2a-f94f171072f8" => Async(reader),
            "6da9a61e-f8c7-4874-be62-68bc5630df71" => Scopes(reader),
            "83c563c4-b4f3-47d5-b824-ba5441477ea8" => new {
                type = "dynamicFlags", storedBits = bytes.Length * 8,
                setBits = bytes.Sum(value => BitOperations.PopCount((uint)value))
            },
            "ed9fdf71-8879-4747-8ed3-fe5ede3ce710" => new { type = "tupleNames", names = Strings(reader) },
            "58b2eab6-209f-4e4e-a22c-b2d0f910c782" => new { type = "defaultNamespace", name = Encoding.UTF8.GetString(bytes) },
            "932e74bc-dba9-4478-8d46-0f32a7bab3d3" => Documents(reader),
            "9d40ace1-c703-4d0e-bf41-7243060a8fb5" => new { type = "primaryConstructor" },
            _ => null
        };
    }

    static object? Member(object value, string name) => value.GetType()
        .GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(value)
        ?? value.GetType().GetProperty(name)?.GetValue(value);

    static object Enc(string id, byte[] bytes) {
        var data = ImmutableArray.Create(bytes);
        object decoded = EditAndContinueMethodDebugInformation.Create(
            id.StartsWith("755f") ? data : default,
            id.StartsWith("a643") ? data : default,
            id.StartsWith("8b78") ? data : default);
        if (id.StartsWith("755f")) {
            var slots = ((IEnumerable)Member(decoded, "LocalSlots")!).Cast<object>().ToArray();
            return new { type = "encSlots", slots = slots.Length,
                temporaries = slots.Count(slot => Member(slot, "SynthesizedKind")!.ToString() == "LoweringTemp"),
                ordinalSlots = slots.Count(slot => (int)Member(Member(slot, "Id")!, "Ordinal")! > 0) };
        }
        if (id.StartsWith("a643")) return new { type = "encLambdas",
            closures = (int)Member(Member(decoded, "Closures")!, "Length")!,
            lambdas = (int)Member(Member(decoded, "Lambdas")!, "Length")! };
        return new { type = "encStates", states = (int)Member(Member(decoded, "StateMachineStates")!, "Length")! };
    }

    static string String(ref BlobReader reader) {
        var bytes = new List<byte>();
        byte value;
        while ((value = reader.ReadByte()) != 0) bytes.Add(value);
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    static string[] Strings(BlobReader reader) {
        var values = new List<string>();
        while (reader.RemainingBytes > 0) values.Add(String(ref reader));
        return values.ToArray();
    }

    static object Options(BlobReader reader) {
        var options = new List<object>();
        while (reader.RemainingBytes > 0) options.Add(new { name = String(ref reader), value = String(ref reader) });
        return new { type = "options", options };
    }

    static object References(BlobReader reader) {
        var references = new List<object>();
        while (reader.RemainingBytes > 0) references.Add(new {
            fileName = String(ref reader), aliases = String(ref reader), flags = reader.ReadByte(),
            timeStamp = reader.ReadUInt32(), fileSize = reader.ReadUInt32(), mvid = reader.ReadGuid().ToString()
        });
        return new { type = "references", references };
    }

    static object Async(BlobReader reader) {
        var hasCatchHandler = reader.ReadUInt32() != 0;
        var awaits = 0;
        while (reader.RemainingBytes > 0) {
            reader.ReadUInt32(); reader.ReadUInt32(); reader.ReadCompressedInteger(); awaits++;
        }
        return new { type = "asyncStepping", hasCatchHandler, awaits };
    }

    static object Scopes(BlobReader reader) {
        var scopes = 0;
        var inactiveScopes = 0;
        long totalIlBytes = 0;
        while (reader.RemainingBytes > 0) {
            var start = reader.ReadUInt32();
            var length = reader.ReadUInt32();
            if (start == 0 && length == 0) inactiveScopes++;
            totalIlBytes += length; scopes++;
        }
        return new { type = "hoistedScopes", scopes, inactiveScopes, totalIlBytes };
    }

    static object Documents(BlobReader reader) {
        var documents = new List<int>();
        while (reader.RemainingBytes > 0) documents.Add(reader.ReadCompressedInteger());
        return new { type = "typeDocuments", documents };
    }

    static object SourceLink(byte[] bytes) {
        using var json = JsonDocument.Parse(bytes);
        return new { type = "sourceLink", documents = json.RootElement.GetProperty("documents")
            .EnumerateObject().Select(property => new { pattern = property.Name, url = property.Value.GetString() }).ToArray() };
    }

    static object Source(byte[] bytes) {
        var size = BitConverter.ToInt32(bytes);
        var content = bytes[4..];
        if (size > 0) {
            using var input = new DeflateStream(new MemoryStream(content), CompressionMode.Decompress);
            using var output = new MemoryStream();
            input.CopyTo(output); content = output.ToArray();
        }
        using var textReader = new StreamReader(new MemoryStream(content), Encoding.UTF8, true);
        var text = textReader.ReadToEnd();
        return new { type = "embeddedSource", source = new {
            storage = size > 0 ? "deflate" : "raw", bytes = content.Length,
            lines = text.Length == 0 ? 0 : Regex.Matches(text, "\r\n|\r|\n").Count + 1,
            encoding = textReader.CurrentEncoding.WebName.ToUpperInvariant()
        } };
    }
}
