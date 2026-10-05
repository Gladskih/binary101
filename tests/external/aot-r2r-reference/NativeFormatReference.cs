using Internal.Metadata.NativeFormat;
using System.Reflection;
using System.Text.Json;

// Execute the upstream generated reader, rather than reproducing its field layouts.
sealed class NativeFormatReference(MetadataReader reader)
{
    readonly Queue<object> pending = new();
    readonly HashSet<(int, int)> visited = new();
    readonly Dictionary<Type, MethodInfo> getters = typeof(MetadataReader).GetMethods()
        .Where(method => method.Name.StartsWith("Get") && method.GetParameters().Length == 1)
        .ToDictionary(method => method.GetParameters()[0].ParameterType);

    static (int type, int offset) Describe(object handle)
    {
        var kind = handle is Handle generic ? generic.HandleType :
            Enum.Parse<HandleType>(handle.GetType().Name[..^6]);
        var offset = (int)handle.GetType().GetProperty("Offset",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).GetValue(handle);
        return ((int)kind, offset);
    }

    object TypedHandle(object handle, int kind)
    {
        if (handle is not Handle generic) return handle;
        var type = getters.Keys.First(type => type.Name == ((HandleType)kind) + "Handle");
        return Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.NonPublic,
            null, new object[] { generic._value }, null);
    }

    object Normalize(object value)
    {
        if (value == null) return null;
        var type = value.GetType();
        if (value is Handle || type.Name.EndsWith("Handle"))
        {
            var handle = Describe(value);
            if (handle.offset != 0) pending.Enqueue(value);
            return new { handle.type, handle.offset };
        }
        if (type.IsEnum) return Convert.ToUInt64(value);
        if (value is long || value is ulong) return value.ToString();
        var enumerate = type.GetMethod("GetEnumerator", Type.EmptyTypes);
        return enumerate != null && value is not string ? Enumerate(value, enumerate) : value;
    }

    object Enumerate(object value, MethodInfo enumerate)
    {
        var enumerator = enumerate.Invoke(value, null);
        var move = enumerator.GetType().GetMethod("MoveNext");
        var current = enumerator.GetType().GetProperty("Current");
        var items = new List<object>();
        while ((bool)move.Invoke(enumerator, null)) items.Add(Normalize(current.GetValue(enumerator)));
        return items;
    }

    List<object> Records()
    {
        foreach (var handle in reader.ScopeDefinitions) pending.Enqueue(handle);
        var records = new List<object>();
        while (pending.TryDequeue(out var untyped))
        {
            var key = Describe(untyped);
            if (!visited.Add(key)) continue;
            var handle = TypedHandle(untyped, key.type);
            var record = getters[handle.GetType()].Invoke(reader, new object[] { handle });
            var fields = record.GetType().GetProperties().ToDictionary(property => property.Name,
                property => Normalize(property.GetValue(record)));
            records.Add(new { key.type, key.offset, fields });
        }
        return records;
    }

    public static unsafe void Export(string input, string output)
    {
        var bytes = File.ReadAllBytes(input);
        fixed (byte* pointer = bytes)
        {
            var records = new NativeFormatReference(new MetadataReader((IntPtr)pointer, bytes.Length))
                .Records();
            File.WriteAllText(output, JsonSerializer.Serialize(records));
            Console.Error.WriteLine($"Read {records.Count} NativeFormat records with upstream .NET reader");
        }
    }
}
