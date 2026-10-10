using System.Runtime.InteropServices;

// The executable reports its own loaded, hydrated descriptors. The external test reads the
// file separately, so its oracle does not consume production parser output or guessed offsets.
[StructLayout(LayoutKind.Sequential)]
struct Mixed
{
    public long Leading;
    public object First;
    public long Between;
    public object Second;
    public object Third;
}

static partial class Program
{
    [LibraryImport("kernel32", EntryPoint = "GetModuleHandleW")]
    private static partial nint ModuleHandle(nint name);

    static unsafe void Report(string name, object instance)
    {
        byte* table = (byte*)instance.GetType().TypeHandle.Value;
        long count = *((nint*)table - 1);
        long size = (count > 0 ? count * 2 + 1 : -count + 2) * sizeof(nint);
        string bytes = Convert.ToHexString(new ReadOnlySpan<byte>(table - size, checked((int)size)));
        Console.WriteLine($"{name} {(nint)table - ModuleHandle(0)} {*(uint*)table} " +
            $"{*(uint*)(table + 4)} {*(ushort*)(table + 8 + sizeof(nint))} {bytes}");
        GC.KeepAlive(instance);
    }

    static void Main()
    {
        Report("references", new object[2]);
        Report("repeating", new Mixed[2]);
        Report("multidimensional", new Mixed[2, 3]);
        Report("boxed", new Mixed { First = new object(), Second = new object(), Third = new object() });
    }
}
