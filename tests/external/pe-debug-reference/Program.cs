using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// Independent oracle: unchanged .NET System.Reflection.Metadata APIs.
// https://github.com/dotnet/runtime/tree/main/src/libraries/System.Reflection.Metadata
if (args.Length == 0) {
    await AsyncSample(IteratorSample(3).Sum());
    return;
}
using var input = File.OpenRead(args[0]);
using var pe = new PEReader(input);
var entries = pe.ReadDebugDirectory();
var embedded = entries.Where(entry => entry.Type == DebugDirectoryEntryType.EmbeddedPortablePdb)
    .Select(entry => {
        using var provider = pe.ReadEmbeddedPortablePdbDebugDirectoryData(entry);
        var reader = provider.GetMetadataReader();
        var id = reader.DebugMetadataHeader!.Id.AsSpan();
        var documents = reader.Documents.Select(handle => {
            var document = reader.GetDocument(handle);
            return new {
                name = reader.GetString(document.Name),
                language = reader.GetGuid(document.Language).ToString(),
                hashAlgorithm = reader.GetGuid(document.HashAlgorithm).ToString(),
                hashSize = reader.GetBlobBytes(document.Hash).Length
            };
        }).ToArray();
        var methods = reader.MethodDebugInformation.Select(reader.GetMethodDebugInformation).ToArray();
        var points = methods.SelectMany(method => method.GetSequencePoints()).ToArray();
        return new {
            id = new { guid = new Guid(id[..16]).ToString(), stamp = BinaryPrimitives.ReadUInt32LittleEndian(id[16..]) },
            documents,
            locals = reader.LocalVariables.Select(handle => {
                var local = reader.GetLocalVariable(handle);
                return (object)new { kind = "variable", name = reader.GetString(local.Name),
                    slot = local.Index, attributes = (int)local.Attributes };
            }).Concat(reader.LocalConstants.Select(handle => {
                var local = reader.GetLocalConstant(handle);
                return (object)new { kind = "constant", name = reader.GetString(local.Name),
                    signatureSize = reader.GetBlobBytes(local.Signature).Length };
            })).ToArray(),
            tables = Enumerable.Range(0x30, 8).Select(table => new {
                name = ((TableIndex)table).ToString(), rows = reader.GetTableRowCount((TableIndex)table)
            }).Where(table => table.rows != 0).ToArray(),
            methodsWithSequencePoints = methods.Count(method => !method.SequencePointsBlob.IsNil),
            sequencePoints = new { visible = points.Count(point => !point.IsHidden), hidden = points.Count(point => point.IsHidden) },
            customRecords = reader.CustomDebugInformation.Select(handle => {
                var record = reader.GetCustomDebugInformation(handle);
                return new { kind = reader.GetGuid(record.Kind).ToString(), size = reader.GetBlobBytes(record.Value).Length };
            }).ToArray()
        };
    }).ToArray();
Console.WriteLine(JsonSerializer.Serialize(new {
    types = entries.Select(entry => (int)entry.Type).ToArray(), embedded
}));

// These compiler-produced methods exercise async state machines, iterator scopes,
// constants and local variables in the same PE used as the oracle's sample.
static async Task<int> AsyncSample(int value) {
    const int multiplier = 3;
    await Task.Yield();
    var result = value * multiplier;
    return result;
}
static IEnumerable<int> IteratorSample(int value) {
    for (var index = 0; index < value; index++) yield return index;
}
