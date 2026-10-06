using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Marshalled
{
    public int Number;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string Name;
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int Callback(int value);

public class Generic<T>
{
    public static string Name;
    static Generic() { Name = typeof(T).Name + DateTime.UtcNow.Ticks; }
}

public interface IGvm { T Transform<T>(T value); }
public class Gvm : IGvm
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public T Transform<T>(T value) => value;
}

class SeedSample
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    static IGvm Factory() => new Gvm();
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static T Identity<T>(T value) => value;
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Transform(int value) => value + 7;

    static void Marshalling()
    {
        var memory = Marshal.AllocHGlobal(Marshal.SizeOf<Marshalled>());
        Marshal.StructureToPtr(new Marshalled { Number = 42, Name = "seed" }, memory, false);
        Console.WriteLine(Marshal.PtrToStructure<Marshalled>(memory).Name);
        Marshal.DestroyStructure<Marshalled>(memory);
        Marshal.FreeHGlobal(memory);
        Callback callback = Transform;
        var pointer = Marshal.GetFunctionPointerForDelegate(callback);
        Console.WriteLine(Marshal.GetDelegateForFunctionPointer<Callback>(pointer)(42));
        GC.KeepAlive(callback);
    }

    static void Main()
    {
        Marshalling();
        Console.WriteLine(Generic<string>.Name);
        Console.WriteLine(Generic<object>.Name);
        var method = typeof(SeedSample).GetMethod(nameof(Identity))!.MakeGenericMethod(typeof(int));
        Console.WriteLine(method.Invoke(null, new object[] { 42 }));
        Func<string, string> identity = Identity<string>;
        Console.WriteLine(identity("typed"));
        Console.WriteLine(Identity(42));
        Console.WriteLine(Factory().Transform<int>(42));
    }
}
