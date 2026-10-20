using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// Independent oracle: unchanged .NET System.Reflection.Metadata APIs.
// https://github.com/dotnet/runtime/tree/main/src/libraries/System.Reflection.Metadata
if (args.Length == 0) {
    ConstantsSample();
    await AsyncSample(IteratorSample(3).Sum());
    return;
}
using var input = File.OpenRead(args[0]);
using var pe = new PEReader(input);
var entries = pe.ReadDebugDirectory();
var systemMetadata = pe.GetMetadataReader();
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
            imports = reader.ImportScopes.Select(handle => {
                var scope = reader.GetImportScope(handle);
                return new { parent = MetadataTokens.GetRowNumber(scope.Parent), imports = scope.GetImports().Select(import => {
                    var value = new Dictionary<string, object?> { ["kind"] = (int)import.Kind };
                    if ((int)import.Kind is 4 or 5 or 6 or 7 or 8 or 9) value["alias"] = System.Text.Encoding.UTF8.GetString(reader.GetBlobBytes(import.Alias));
                    if ((int)import.Kind is 1 or 2 or 4 or 7 or 8) value["targetNamespace"] = System.Text.Encoding.UTF8.GetString(reader.GetBlobBytes(import.TargetNamespace));
                    if ((int)import.Kind is 2 or 6 or 8) value["targetAssembly"] = MetadataTokens.GetRowNumber(import.TargetAssembly);
                    if ((int)import.Kind is 3 or 9) value["targetType"] = new {
                        tableId = MetadataTokens.GetToken(import.TargetType) >> 24, row = MetadataTokens.GetRowNumber(import.TargetType)
                    };
                    return value;
                }).ToArray() };
            }).ToArray(),
            locals = reader.LocalVariables.Select(handle => {
                var local = reader.GetLocalVariable(handle);
                return (object)new { kind = "variable", name = reader.GetString(local.Name),
                    slot = local.Index, attributes = (int)local.Attributes };
            }).Concat(reader.LocalConstants.Select(handle => {
                var local = reader.GetLocalConstant(handle);
                return (object)new { kind = "constant", name = reader.GetString(local.Name),
                    signatureSize = reader.GetBlobBytes(local.Signature).Length };
            })).ToArray(),
            constantValues = reader.LocalConstants.Select(handle => {
                var local = reader.GetLocalConstant(handle);
                return new { name = reader.GetString(local.Name),
                    constant = ConstantRecords.Decode(reader.GetBlobReader(local.Signature), systemMetadata) };
            }).ToArray(),
            tables = Enumerable.Range(0x30, 8).Select(table => new {
                name = ((TableIndex)table).ToString(), rows = reader.GetTableRowCount((TableIndex)table)
            }).Where(table => table.rows != 0).ToArray(),
            methodsWithSequencePoints = methods.Count(method => !method.SequencePointsBlob.IsNil),
            sequencePoints = new { visible = points.Count(point => !point.IsHidden), hidden = points.Count(point => point.IsHidden) },
            customRecords = reader.CustomDebugInformation.Select(handle => {
                var record = reader.GetCustomDebugInformation(handle);
                var kind = reader.GetGuid(record.Kind);
                return new { kind = kind.ToString(), size = reader.GetBlobBytes(record.Value).Length,
                    parent = new { tableId = MetadataTokens.GetToken(record.Parent) >> 24, row = MetadataTokens.GetRowNumber(record.Parent) },
                    data = CustomRecords.Decode(kind, reader.GetBlobReader(record.Value)) };
            }).ToArray()
        };
    }).ToArray();
Console.WriteLine(JsonSerializer.Serialize(new {
    types = entries.Select(entry => (int)entry.Type).ToArray(), embedded, kinds = CustomRecords.Kinds()
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

static void ConstantsSample() {
    const decimal price = 12.34m;
    const string text = "<constant>";
    const ulong maximum = ulong.MaxValue;
    const long negative = -42;
    const DayOfWeek day = DayOfWeek.Friday;
    const double ratio = -0.5;
    const bool enabled = true;
    const char initial = 'A';
    dynamic dynamicValue = 3;
    (int First, int Second) pair = (1, 2);
    GC.KeepAlive((price, text, maximum, negative, day, ratio, enabled, initial, (object)dynamicValue, pair));
}
