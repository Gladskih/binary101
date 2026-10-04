using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

// The oracle delegates binary decoding to Microsoft's System.Reflection.Metadata.
// This provider only chooses a stable text notation for comparing decoded types.
sealed class SignatureNames : ISignatureTypeProvider<string, object?>
{
    public string GetArrayType(string element, ArrayShape shape)
    {
        var dimensions = Enumerable.Range(0, shape.Rank).Select(index =>
        {
            int? size = index < shape.Sizes.Length ? shape.Sizes[index] : null;
            int? bound = index < shape.LowerBounds.Length ? shape.LowerBounds[index] : null;
            if (size == null) return bound == null ? "" : $"{bound}...";
            return bound == null ? $"size {size}" : $"{bound}...{bound + size - 1}";
        }).ToArray();
        return $"{element}[{(shape.Rank == 1 && dimensions[0] == "" ? "*" : string.Join(",", dimensions))}]";
    }

    public string GetByReferenceType(string element) => element + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) =>
        $"fnptr ({string.Join(", ", signature.ParameterTypes)}) -> {signature.ReturnType}";
    public string GetGenericInstantiation(string type, ImmutableArray<string> arguments) =>
        $"{type}<{string.Join(", ", arguments)}>";
    public string GetGenericMethodParameter(object? context, int index) => $"mvar {index}";
    public string GetGenericTypeParameter(object? context, int index) => $"var {index}";
    public string GetModifiedType(string modifier, string type, bool required) =>
        $"{type} {(required ? "modreq" : "modopt")} {modifier}";
    public string GetPinnedType(string element) => element + " pinned";
    public string GetPointerType(string element) => element + "*";
    public string GetSZArrayType(string element) => element + "[]";

    public string GetPrimitiveType(PrimitiveTypeCode code) => code switch
    {
        PrimitiveTypeCode.Void => "void", PrimitiveTypeCode.Boolean => "bool",
        PrimitiveTypeCode.Char => "char", PrimitiveTypeCode.SByte => "i1",
        PrimitiveTypeCode.Byte => "u1", PrimitiveTypeCode.Int16 => "i2",
        PrimitiveTypeCode.UInt16 => "u2", PrimitiveTypeCode.Int32 => "i4",
        PrimitiveTypeCode.UInt32 => "u4", PrimitiveTypeCode.Int64 => "i8",
        PrimitiveTypeCode.UInt64 => "u8", PrimitiveTypeCode.Single => "r4",
        PrimitiveTypeCode.Double => "r8", PrimitiveTypeCode.String => "string",
        PrimitiveTypeCode.TypedReference => "typedref", PrimitiveTypeCode.IntPtr => "native int",
        PrimitiveTypeCode.UIntPtr => "native uint", PrimitiveTypeCode.Object => "object",
        _ => throw new BadImageFormatException($"Unsupported primitive {code}")
    };

    static string TypeName(string table, int row, byte kind) =>
        (kind == 0x11 ? "valuetype " : kind == 0x12 ? "class " : "") + $"{table}#{row}";

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte kind) =>
        TypeName("TypeDef", MetadataTokens.GetRowNumber(handle), kind);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte kind) =>
        TypeName("TypeRef", MetadataTokens.GetRowNumber(handle), kind);
    public string GetTypeFromSpecification(MetadataReader reader, object? context,
        TypeSpecificationHandle handle, byte kind) =>
        TypeName("TypeSpec", MetadataTokens.GetRowNumber(handle), kind);
}
