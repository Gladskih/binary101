using System.Globalization;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

static class ConstantRecords {
    static object Reference(EntityHandle handle) => new {
        tableId = MetadataTokens.GetToken(handle) >> 24, row = MetadataTokens.GetRowNumber(handle)
    };

    static string? TypeName(EntityHandle handle, MetadataReader metadata) => handle.Kind switch {
        HandleKind.TypeReference => metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)handle).Namespace)
            + "." + metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)handle).Name),
        HandleKind.TypeDefinition => metadata.GetString(metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Namespace)
            + "." + metadata.GetString(metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Name),
        _ => null
    };

    public static object Decode(BlobReader reader, MetadataReader metadata) {
        var result = new Dictionary<string, object?>();
        var modifiers = new List<object>();
        var code = reader.ReadByte();
        while (code is 31 or 32) {
            modifiers.Add(new { required = code == 31, typeReference = Reference(reader.ReadTypeHandle()) });
            code = reader.ReadByte();
        }
        result["typeCode"] = code;
        if (modifiers.Count > 0) result["modifiers"] = modifiers;
        if (code is 17 or 18) {
            var type = reader.ReadTypeHandle();
            result["typeReference"] = Reference(type);
            if (reader.RemainingBytes > 0 && TypeName(type, metadata) == "System.Decimal")
                result["value"] = reader.ReadDecimal().ToString(CultureInfo.InvariantCulture);
            else if (reader.RemainingBytes > 0 && TypeName(type, metadata) == "System.DateTime")
                result["value"] = new DateTime(reader.ReadInt64()).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
            else result["data"] = reader.ReadBytes(reader.RemainingBytes).Select(value => (int)value).ToArray();
            return result;
        }
        if (code == 28) result["value"] = null;
        else if (code == 14) result["value"] = reader.RemainingBytes == 1
            ? null : reader.ReadUTF16(reader.RemainingBytes);
        else {
            var value = reader.ReadConstant((ConstantTypeCode)code);
            result["value"] = code is 10 or 11 ? Convert.ToString(value, CultureInfo.InvariantCulture)
                : code == 3 ? value?.ToString() : value;
            if (reader.RemainingBytes > 0) result["typeReference"] = Reference(reader.ReadTypeHandle());
        }
        return result;
    }
}
