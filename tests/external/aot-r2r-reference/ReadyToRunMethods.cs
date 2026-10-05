using ILCompiler.Reflection.ReadyToRun;

static class ReadyToRunMethods
{
    // ReadyToRunReader.GetRuntimeFunctionIndexFromOffset, v10.0.0.
    public static List<object> Read(byte[] bytes)
    {
        var reader = new NativeReader(new MemoryStream(bytes));
        var array = new NativeArray(reader, 0);
        var methods = new List<object>();
        for (uint index = 0; index < array.GetCount(); index++)
        {
            int position = 0;
            if (!array.TryGetAt(index, ref position)) continue;
            uint value = 0;
            int next = (int)reader.DecodeUnsigned((uint)position, ref value);
            int? fixups = null;
            if ((value & 1) != 0)
            {
                if ((value & 2) != 0)
                {
                    uint distance = 0;
                    reader.DecodeUnsigned((uint)next, ref distance);
                    next -= (int)distance;
                }
                fixups = next;
                value >>= 2;
            }
            else value >>= 1;
            methods.Add(new { methodRid = index + 1, runtimeFunctionIndex = value, fixupOffset = fixups });
        }
        return methods;
    }
}
