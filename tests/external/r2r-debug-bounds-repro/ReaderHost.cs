using System.Reflection.PortableExecutable;

// Host objects only: all byte decoding is done by unmodified upstream sources.
namespace ILCompiler.Reflection.ReadyToRun;

public sealed class ReadyToRunReader
{
    public NativeReader ImageReader { get; init; }
    public Machine Machine { get; init; }
    public ReadyToRunHeader ReadyToRunHeader { get; init; }
}
public sealed class ReadyToRunHeader
{
    public int MajorVersion { get; init; }
}
public sealed class RuntimeFunction
{
    public ReadyToRunReader ReadyToRunReader { get; init; }
    public DebugMethod Method { get; } = new();
}
public sealed class DebugMethod
{
    public DebugSignature Signature { get; } = new();
}
public sealed class DebugSignature
{
    public object[] ParameterTypes { get; } = [];
}

// This switch label is declared in ReadyToRunReader.cs in current upstream.
// https://github.com/dotnet/runtime/blob/0e45f6c8d90db0acaa0c8b671fc9b0f4da383a06/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
public static class WasmMachine
{
    public const Machine Wasm32 = (Machine)0xFFFE;
}
