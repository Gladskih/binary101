using System.Reflection.PortableExecutable;

// Minimal host objects for the unmodified upstream DebugInfo.cs. This adapter supplies
// version, machine and bytes only; the upstream reader performs all payload decoding.
// Parameter/local classification is deliberately excluded from the exported comparison.
namespace ILCompiler.Reflection.ReadyToRun
{
    public sealed class ReadyToRunReader
    {
        public required NativeReader ImageReader { get; init; }
        public required Machine Machine { get; init; }
        public required ReadyToRunHeader ReadyToRunHeader { get; init; }
    }
    public sealed class ReadyToRunHeader
    {
        public required int MajorVersion { get; init; }
    }
    public sealed class RuntimeFunction
    {
        public required ReadyToRunReader ReadyToRunReader { get; init; }
        public DebugMethod Method { get; } = new();
    }
    public sealed class DebugMethod
    {
        public DebugSignature Signature { get; } = new();
    }
    public sealed class DebugSignature
    {
        public object[] ParameterTypes { get; } = Array.Empty<object>();
    }
}
