using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;

// Test adapter for map2dbg/tds2pdb, compiled from unchanged upstream sources at
// 70cd89ff693cd622215309b0acb4326e530e7884. ParseTds supplies the main results.
// ClassTypes/TypeBodies walk the directory/index and prepare private reference
// slots before calling unchanged upstream body readers. Record contents are decoded
// independently, but the adapter's directory traversal is not an independent oracle.
// This executable is external test tooling, never part of browser analysis.
class Oracle
{
    static object Field(object value, string name)
    {
        return value.GetType().GetField(name).GetValue(value);
    }

    static IEnumerable<object> Items(object value)
    {
        return value == null ? Enumerable.Empty<object>() : ((IEnumerable)value).Cast<object>();
    }

    static object Symbol(object value)
    {
        var name = value.GetType().GetField("Name");
        var compiler = value.GetType().GetField("Compiler");
        return new { kind = value.GetType().Name,
            name = name == null ? null : name.GetValue(value),
            compiler = compiler == null ? null : compiler.GetValue(value), fields = Fields(value) };
    }

    static Dictionary<string, object> Fields(object value)
    {
        var result = new Dictionary<string, object>();
        foreach (var field in value.GetType().GetFields())
        {
            var item = field.GetValue(value);
            if (item == null) continue;
            var type = item.GetType();
            if (type.IsEnum) result.Add(field.Name, Convert.ToInt32(item));
            else if (type.IsPrimitive || item is string) result.Add(field.Name, item);
            else if (type.GetField("Index") != null) result.Add(field.Name, Field(item, "Index"));
            else if (type.GetMethod("GetValue", Type.EmptyTypes) != null)
                result.Add(field.Name, Convert.ToString(type.GetMethod("GetValue").Invoke(item, null),
                    System.Globalization.CultureInfo.InvariantCulture));
            else if (item is IEnumerable)
                result.Add(field.Name, Items(item).Select(entry => entry.GetType().GetField("Index") != null
                    ? Field(entry, "Index") : entry).ToArray());
            else if (type.IsValueType) result.Add(field.Name, Fields(item));
        }
        return result;
    }

    static object Source(object value)
    {
        return new { name = Field(value, "Name"),
            segments = Items(Field(value, "Ranges")).Select(range => new {
                segment = Field(range, "SegIndex"), start = Field(range, "StartOffset"),
                end = Field(range, "EndOffset"), lines = Items(Field(range, "Lines")).Select(line =>
                    new { offset = Field(line, "Offset"), line = Field(line, "LineNo") }).ToArray()
            }).ToArray() };
    }

    static object Module(object value)
    {
        var sources = Field(value, "Sources");
        return new { name = Field(value, "Name"),
            segments = Items(Field(value, "CodeSegs")).Select(segment => new {
                segment = Field(segment, "SegIndex"), flags = Field(segment, "Flags"),
                offset = Field(segment, "Offset"), size = Field(segment, "Length") }).ToArray(),
            files = sources == null ? new object[0] : Items(Field(sources, "SourceFiles")).Select(Source).ToArray(),
            symbols = Items(Field(value, "Symbols")).Select(Symbol).ToArray() };
    }

    static object[] ClassTypes(Type program, string path)
    {
        var bytes = File.ReadAllBytes(path);
        int directory = BitConverter.ToInt32(bytes, 4);
        int count = BitConverter.ToInt32(bytes, directory + 4);
        var result = new List<object>();
        var read = program.Assembly.GetType("tds2pdbproto.TypStruct").GetMethod("Read");
        for (int entry = 0; entry < count; entry++)
        {
            int current = directory + 16 + entry * 12;
            if (BitConverter.ToUInt16(bytes, current) != 0x12b) continue;
            int start = BitConverter.ToInt32(bytes, current + 4);
            int records = BitConverter.ToInt32(bytes, start + 4);
            // ParseTds skips its type-table allocation. Supply the same empty
            // reference slots its original decoder expects; no types are fabricated
            // or resolved. TypStruct.Read itself and its name decoder are unchanged.
            program.GetField("types", BindingFlags.Static | BindingFlags.NonPublic).SetValue(null,
                Array.CreateInstance(program.Assembly.GetType("tds2pdbproto.TypeInfo"), records));
            for (int index = 0; index < records; index++)
            {
                int offset = start + BitConverter.ToInt32(bytes, start + 8 + index * 4);
                int kind = BitConverter.ToUInt16(bytes, offset + 2);
                if (kind != 4 && kind != 5) continue;
                using (var stream = new MemoryStream(bytes, offset + 4, bytes.Length - offset - 4))
                using (var reader = new BinaryReader(stream))
                {
                    var value = read.Invoke(null, new object[] { kind == 4, reader });
                    result.Add(new { index = index, name = Field(value, "Name"), fields = Fields(value) });
                }
            }
        }
        return result.ToArray();
    }

    static object[] TypeBodies(Type program, string path)
    {
        var bytes = File.ReadAllBytes(path);
        int directory = BitConverter.ToInt32(bytes, 4);
        int count = BitConverter.ToInt32(bytes, directory + 4);
        var result = new List<object>();
        var readers = new Dictionary<int, string> { {1, "TypModifier"}, {2, "TypPointer"},
            {8, "TypProcedure"}, {9, "TypMFunction"}, {0x201, "TypArgList"} };
        for (int entry = 0; entry < count; entry++)
        {
            int current = directory + 16 + entry * 12;
            if (BitConverter.ToUInt16(bytes, current) != 0x12b) continue;
            int start = BitConverter.ToInt32(bytes, current + 4);
            int records = BitConverter.ToInt32(bytes, start + 4);
            program.GetField("types", BindingFlags.Static | BindingFlags.NonPublic).SetValue(null,
                Array.CreateInstance(program.Assembly.GetType("tds2pdbproto.TypeInfo"), records));
            for (int index = 0; index < records; index++)
            {
                int offset = start + BitConverter.ToInt32(bytes, start + 8 + index * 4);
                int kind = BitConverter.ToUInt16(bytes, offset + 2);
                if (!readers.ContainsKey(kind)) continue;
                var read = program.Assembly.GetType("tds2pdbproto." + readers[kind]).GetMethod("Read",
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                using (var stream = new MemoryStream(bytes, offset + 4, bytes.Length - offset - 4))
                using (var reader = new BinaryReader(stream))
                    result.Add(new { index = index, kind = kind, fields = Fields(read.Invoke(null, new object[] { reader })) });
            }
        }
        return result.ToArray();
    }

    static object[] TranslatedNames(Type program)
    {
        var names = (string[])program.GetField("names", BindingFlags.Static | BindingFlags.NonPublic).GetValue(null);
        var translate = program.Assembly.GetType("tds2pdbproto.NameTranslator").GetMethod("TranslateUdtName");
        return names.Select(name => translate.Invoke(null, new object[] { name })).ToArray();
    }

    static void Main(string[] args)
    {
        var stdout = Console.Out;
        var diagnostics = new StringWriter();
        Console.SetOut(diagnostics);
        var program = Assembly.LoadFrom(args[0]).GetType("tds2pdbproto.Program");
        using (var stream = File.OpenRead(args[1]))
            program.GetMethod("ParseTds", BindingFlags.Static | BindingFlags.NonPublic)
                .Invoke(null, new object[] { stream });
        var flags = BindingFlags.Static | BindingFlags.NonPublic;
        var serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        var result = new {
            names = program.GetField("names", flags).GetValue(null),
            modules = Items(program.GetField("modules", flags).GetValue(null)).Select(Module).ToArray(),
            globals = Items(program.GetField("globalSymbols", flags).GetValue(null)).Select(Symbol).ToArray(),
            classTypes = ClassTypes(program, args[1]),
            typeBodies = TypeBodies(program, args[1]),
            translatedNames = TranslatedNames(program)
        };
        stdout.WriteLine(serializer.Serialize(new { result.names, result.modules, result.globals,
            result.classTypes, result.typeBodies, result.translatedNames, diagnostics = diagnostics.ToString() }));
    }
}
