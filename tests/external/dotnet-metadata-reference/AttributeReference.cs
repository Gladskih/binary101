using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

// Resolves only types declared in this assembly. Missing dependencies do not justify guessing enums.
sealed class AttributeNames(MetadataReader metadata) : ICustomAttributeTypeProvider<string>
{
    readonly Dictionary<string, TypeDefinition> definitions = metadata.TypeDefinitions
        .GroupBy(handle => DefinitionName(metadata, handle))
        .Where(group => group.Count() == 1).ToDictionary(group => group.Key,
            group => metadata.GetTypeDefinition(group.Single()));

    static string DefinitionName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var names = new List<string>();
        while (!handle.IsNil) {
            var type = reader.GetTypeDefinition(handle);
            handle = type.GetDeclaringType();
            names.Add(handle.IsNil ? FullName(reader, type.Namespace, type.Name) : reader.GetString(type.Name));
        }
        names.Reverse();
        return string.Join("+", names);
    }

    static string FullName(MetadataReader reader, StringHandle space, StringHandle name) =>
        reader.GetString(space) is { Length: > 0 } prefix ? prefix + "." + reader.GetString(name) : reader.GetString(name);

    public string GetPrimitiveType(PrimitiveTypeCode code) => new SignatureNames().GetPrimitiveType(code);
    public string GetSystemType() => "System.Type";
    public bool IsSystemType(string type) => type == "System.Type";
    public string GetSZArrayType(string element) => element + "[]";
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte kind)
    {
        return DefinitionName(reader, handle);
    }
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte kind)
    {
        var reference = reader.GetTypeReference(handle);
        var name = FullName(reader, reference.Namespace, reference.Name);
        return name == "System.Type" ? name : "external " + name;
    }

    public string GetTypeFromSerializedName(string name)
    {
        var identity = name.Split(',').Select(part => part.Trim()).ToArray();
        if (identity.Length > 1 && identity[1] != metadata.GetString(metadata.GetAssemblyDefinition().Name))
            throw new BadImageFormatException("External serialized enum type");
        return identity[0];
    }

    public PrimitiveTypeCode GetUnderlyingEnumType(string type)
    {
        if (!definitions.TryGetValue(type, out var definition)) throw new BadImageFormatException("Unresolved enum " + type);
        var field = definition.GetFields().Select(metadata.GetFieldDefinition)
            .SingleOrDefault(field => metadata.GetString(field.Name) == "value__");
        if (field.Signature.IsNil) throw new BadImageFormatException("Missing enum value__ field");
        return field.DecodeSignature(new SignatureNames(), null) switch {
            "i1" => PrimitiveTypeCode.SByte, "u1" => PrimitiveTypeCode.Byte,
            "i2" => PrimitiveTypeCode.Int16, "u2" => PrimitiveTypeCode.UInt16,
            "i4" => PrimitiveTypeCode.Int32, "u4" => PrimitiveTypeCode.UInt32,
            "i8" => PrimitiveTypeCode.Int64, "u8" => PrimitiveTypeCode.UInt64,
            _ => throw new BadImageFormatException("Invalid enum field type")
        };
    }
}

static class AttributeReference
{
    static object? Value(object? value) => value switch {
        ImmutableArray<CustomAttributeTypedArgument<string>> array =>
            string.Join(", ", array.Select(argument => Value(argument.Value)?.ToString() ?? "null")),
        long integer => integer.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ulong integer => $"0x{integer:x16}", char character => character.ToString(),
        double number when !double.IsFinite(number) => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float number when !float.IsFinite(number) => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float number => (double)number,
        _ => value
    };

    public static object[] Read(MetadataReader reader)
    {
        var names = new AttributeNames(reader);
        var values = new List<object>();
        foreach (var handle in reader.CustomAttributes)
        {
            try
            {
                var decoded = reader.GetCustomAttribute(handle).DecodeValue(names);
                values.Add(new { row = MetadataTokens.GetRowNumber(handle),
                    fixedArguments = decoded.FixedArguments.Select(argument => Value(argument.Value)).ToArray(),
                    namedArguments = decoded.NamedArguments.Select(argument => new {
                        kind = argument.Kind == CustomAttributeNamedArgumentKind.Field ? "field" : "property",
                        name = argument.Name, value = Value(argument.Value)
                    }).ToArray() });
            }
            // Missing external enum dependencies and malformed values cannot provide reference values.
            catch (BadImageFormatException) { }
        }
        return values.ToArray();
    }
}
