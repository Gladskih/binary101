using dnlib.DotNet;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

static class BlobReference
{
    static object? Scalar(object? value) => value switch {
        UTF8String text => text.String,
        long integer => integer.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ulong integer => $"0x{integer:x16}", char character => character.ToString(),
        double number when !double.IsFinite(number) => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float number when !float.IsFinite(number) => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float number => (double)number,
        _ => value
    };

    static object? Constant(MetadataReader reader, int row)
    {
        var constant = reader.GetConstant(MetadataTokens.ConstantHandle(row));
        var blob = reader.GetBlobReader(constant.Value);
        // JSON encoders replace unpaired surrogates. Export raw UTF-16 units to avoid data loss.
        if (constant.TypeCode is ConstantTypeCode.Char or ConstantTypeCode.String) {
            var units = new List<int>();
            while (blob.RemainingBytes > 0) units.Add(blob.ReadUInt16());
            return new { utf16 = units };
        }
        return Scalar(blob.ReadConstant(constant.TypeCode));
    }

    static Dictionary<string, object?> Parameters(MarshalType type)
    {
        var result = new Dictionary<string, object?>();
        void Add(string name, int value) { if (value >= 0) result.Add(name, value); }
        switch (type) {
            case FixedSysStringMarshalType text: Add("size", text.Size); break;
            case FixedArrayMarshalType array:
                Add("size", array.Size); Add("elementType", (int)array.ElementType); break;
            case ArrayMarshalType array:
                Add("elementType", (int)array.ElementType); Add("sizeParameterIndex", array.ParamNumber);
                Add("size", array.Size); Add("flags", array.Flags); break;
            case InterfaceMarshalType face: Add("iidParameterIndex", face.IidParamIndex); break;
            case SafeArrayMarshalType array:
                if (array.IsVariantTypeValid) Add("variantType", (int)array.VariantType);
                if (array.IsUserDefinedSubTypeValid) result["userDefinedType"] = array.UserDefinedSubType.ReflectionFullName;
                break;
            case CustomMarshalType custom:
                result["guid"] = custom.Guid.String; result["nativeTypeName"] = custom.NativeTypeName.String;
                result["marshalerType"] = custom.CustomMarshaler?.ReflectionFullName ?? "";
                result["cookie"] = custom.Cookie.String;
                break;
        }
        return result;
    }

    static object[] Marshal(ModuleDefMD module)
    {
        var result = new List<object>();
        for (uint row = 1; row <= module.TablesStream.FieldMarshalTable.Rows; row++) {
            module.TablesStream.TryReadFieldMarshalRow(row, out var data);
            var type = MarshalBlobReader.Read(module, data.NativeType);
            if (type is RawMarshalType) continue;
            result.Add(new { row, nativeType = type.NativeType.ToString().ToUpperInvariant(), parameters = Parameters(type) });
        }
        return result.ToArray();
    }

    static object[] Security(ModuleDefMD module)
    {
        var result = new List<object>();
        for (uint row = 1; row <= module.TablesStream.DeclSecurityTable.Rows; row++) {
            module.TablesStream.TryReadDeclSecurityRow(row, out var data);
            var blob = module.BlobStream.Read(data.PermissionSet);
            if (blob.Length == 0 || blob[0] != '.') continue;
            var attributes = DeclSecurityReader.Read(module, data.PermissionSet);
            // dnlib returns an empty list on unresolved enum types or malformed input.
            if (attributes.Count == 0 && blob[1] != 0) continue;
            result.Add(new { row, attributes = attributes.Select(attribute => new {
                namedArguments = attribute.NamedArguments.Select(argument => new {
                    kind = argument.IsField ? "field" : "property", name = argument.Name.String,
                    value = Scalar(argument.Value)
                }).ToArray()
            }).ToArray() });
        }
        return result.ToArray();
    }

    public static object Read(string path, MetadataReader reader)
    {
        using var module = ModuleDefMD.Load(path);
        return new { constants = Enumerable.Range(1, reader.GetTableRowCount(TableIndex.Constant))
            .Select(row => new { row, value = Constant(reader, row) }).ToArray(),
            marshal = Marshal(module), security = Security(module) };
    }
}
