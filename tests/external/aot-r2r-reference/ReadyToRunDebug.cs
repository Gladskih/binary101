using System.Reflection.PortableExecutable;
using System.Numerics;
using ILCompiler.Reflection.ReadyToRun;

static class ReadyToRunDebug
{
    static IEnumerable<object> Bounds(NativeReader reader, DebugInfo debug, int entry, int version)
    {
        uint distance = 0;
        int payload = (int)reader.DecodeUnsigned((uint)entry, ref distance);
        if (distance != 0) payload = entry - (int)distance;
        var header = new NibbleReader(reader, payload);
        uint boundsBytes = header.ReadUInt();
        header.ReadUInt();
        if (boundsBytes == 0) return Array.Empty<object>();
        var counts = new NibbleReader(reader, header.GetNextByteOffset());
        uint count = counts.ReadUInt();
        if (version < 16) return debug.BoundsList.Select(bound => (object)new
        {
            nativeOffset = bound.NativeOffset,
            ilOffset = unchecked((int)bound.ILOffset),
            source = (int)bound.SourceTypes
        });
        return PackedBounds(debug, header, counts, count);
    }

    static List<object> PackedBounds(DebugInfo debug, NibbleReader header,
        NibbleReader counts, uint count)
    {
        int nativeBits = FieldWidth(counts);
        int ilBits = FieldWidth(counts);
        var bits = new System.Collections.BitArray(debug.BoundsBytes[(counts.GetNextByteOffset() -
            header.GetNextByteOffset())..]);
        if (count > bits.Length / (2L + nativeBits + ilBits))
            throw new BadImageFormatException("Truncated packed R2R bounds");
        int position = 0;
        BigInteger nativeOffset = 0;
        BigInteger Field(int width)
        {
            BigInteger value = 0;
            for (int bit = 0; bit < width; bit++)
                if (bits[position++]) value |= BigInteger.One << bit;
            return value;
        }
        var bounds = new List<object>();
        for (int index = 0; index < count; index++)
        {
            int source = (int)Field(2);
            nativeOffset += Field(nativeBits);
            if (nativeOffset > uint.MaxValue) throw new BadImageFormatException("R2R native offset overflow");
            BigInteger ilOffset = Field(ilBits) - 3;
            if (ilOffset > long.MaxValue) throw new BadImageFormatException("R2R IL offset overflow");
            bounds.Add(new
            {
                nativeOffset = (uint)nativeOffset,
                ilOffset = (long)ilOffset,
                source = (source & 1) * 16 | (source & 2)
            });
        }
        return bounds;
    }

    static int FieldWidth(NibbleReader counts)
    {
        uint widthMinusOne = counts.ReadUInt();
        if (widthMinusOne >= int.MaxValue)
            throw new BadImageFormatException("Invalid packed R2R field width");
        return (int)widthMinusOne + 1;
    }

    static object Location(VarLoc location) => location.VarLocType switch
    {
        VarLocType.VLT_REG => new { kind = "register", register = location.Data1 },
        VarLocType.VLT_REG_BYREF => new { kind = "register-byref", register = location.Data1 },
        VarLocType.VLT_REG_FP => new { kind = "fp-register", register = location.Data1 },
        VarLocType.VLT_STK => new { kind = "stack", baseRegister = location.Data1, offset = location.Data2 },
        VarLocType.VLT_STK_BYREF => new { kind = "stack-byref", baseRegister = location.Data1, offset = location.Data2 },
        VarLocType.VLT_REG_REG => new { kind = "register-pair", register1 = location.Data1, register2 = location.Data2 },
        VarLocType.VLT_REG_STK => new
        {
            kind = "register-stack",
            register = location.Data1,
            baseRegister = location.Data2,
            offset = location.Data3
        },
        VarLocType.VLT_STK_REG => new
        {
            kind = "stack-register",
            offset = location.Data1,
            baseRegister = location.Data2,
            register = location.Data3
        },
        VarLocType.VLT_STK2 => new { kind = "stack-pair", baseRegister = location.Data1, offset = location.Data2 },
        VarLocType.VLT_FPSTK => new { kind = "fp-stack", index = location.Data1 },
        VarLocType.VLT_FIXED_VA => new { kind = "varargs", offset = location.Data1 },
        _ => throw new BadImageFormatException("Unknown variable location")
    };

    public static List<object> Read(byte[] bytes, int version, Machine machine)
    {
        var reader = new NativeReader(new MemoryStream(bytes));
        var array = new NativeArray(reader, 0);
        var host = new RuntimeFunction
        {
            ReadyToRunReader = new()
            {
                ImageReader = reader,
                Machine = machine,
                ReadyToRunHeader = new() { MajorVersion = version }
            }
        };
        var methods = new List<object>();
        for (uint index = 0; index < array.GetCount(); index++)
        {
            int offset = 0;
            if (!array.TryGetAt(index, ref offset)) continue;
            var debug = new DebugInfo(host, offset);
            methods.Add(new
            {
                runtimeFunctionIndex = index,
                // v10 DebugInfo.ParseBounds reads padding beyond cMap and shifts its byte
                // through UInt32 before assigning UInt64 (losing high bits). For packed bounds
                // use BitArray fields from vm/debuginfostore.cpp; legacy bounds and all variable
                // records still come directly from unmodified upstream DebugInfo.cs.
                bounds = Bounds(reader, debug, offset, version),
                variables = debug.VariablesList.Select(variable => new
                {
                    startOffset = variable.StartOffset,
                    endOffset = variable.EndOffset,
                    variableNumber = unchecked((int)variable.VariableNumber),
                    location = Location(variable.VariableLocation)
                })
            });
        }
        return methods;
    }
}
