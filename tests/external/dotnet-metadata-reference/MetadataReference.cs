using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

static class MetadataReference
{
    static readonly SignatureNames Names = new();

    static object Method(MethodSignature<string> signature)
    {
        var result = new Dictionary<string, object?> {
            ["callingConvention"] = signature.Header.RawValue,
            ["parameterCount"] = signature.ParameterTypes.Length,
            ["returnType"] = signature.ReturnType,
            ["parameterTypes"] = signature.ParameterTypes
        };
        if (signature.Header.IsGeneric) result["genericParameterCount"] = signature.GenericParameterCount;
        if (signature.RequiredParameterCount < signature.ParameterTypes.Length)
            result["sentinelIndex"] = signature.RequiredParameterCount;
        return result;
    }

    static object Field(string type) => new {
        callingConvention = 6, parameterCount = 0, returnType = type, parameterTypes = Array.Empty<string>()
    };

    static object Signature(MetadataReader reader, TableIndex table, int row) => table switch
    {
        TableIndex.MethodDef => Method(reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(row))
            .DecodeSignature(Names, null)),
        TableIndex.Field => Field(reader.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(row))
            .DecodeSignature(Names, null)),
        TableIndex.MemberRef => Member(reader.GetMemberReference(MetadataTokens.MemberReferenceHandle(row))),
        TableIndex.Property => Method(reader.GetPropertyDefinition(MetadataTokens.PropertyDefinitionHandle(row))
            .DecodeSignature(Names, null)),
        TableIndex.TypeSpec => new { type = reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(row))
            .DecodeSignature(Names, null) },
        TableIndex.MethodSpec => new { types = reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(row))
            .DecodeSignature(Names, null) },
        TableIndex.StandAloneSig => Standalone(reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(row))),
        _ => throw new ArgumentOutOfRangeException(nameof(table))
    };

    static object Member(MemberReference member) => member.GetKind() == MemberReferenceKind.Field
        ? Field(member.DecodeFieldSignature(Names, null)) : Method(member.DecodeMethodSignature(Names, null));

    static object Standalone(StandaloneSignature standalone) => standalone.GetKind() == StandaloneSignatureKind.LocalVariables
        ? new { types = standalone.DecodeLocalSignature(Names, null) }
        : Method(standalone.DecodeMethodSignature(Names, null));

    public static object? Read(string path)
    {
        using var stream = File.OpenRead(path);
        using var image = new PEReader(stream);
        if (!image.HasMetadata) return null;
        var reader = image.GetMetadataReader();
        var counts = Enum.GetValues<TableIndex>().Select(table => new {
            tableId = (int)table, rows = reader.GetTableRowCount(table)
        }).Where(count => count.rows != 0).ToArray();
        var signatures = new Dictionary<string, object>();
        foreach (var table in new[] { TableIndex.MethodDef, TableIndex.Field, TableIndex.MemberRef,
            TableIndex.Property, TableIndex.TypeSpec, TableIndex.MethodSpec, TableIndex.StandAloneSig })
        {
            for (var row = 1; row <= reader.GetTableRowCount(table); row++)
                signatures.Add($"{(int)table}:{row}", Signature(reader, table, row));
        }
        return new { path = Path.GetFullPath(path), metadataOffset = image.PEHeaders.MetadataStartOffset,
            metadataSize = image.PEHeaders.MetadataSize, counts, signatures,
            attributes = AttributeReference.Read(reader), blobs = BlobReference.Read(path, reader) };
    }
}
