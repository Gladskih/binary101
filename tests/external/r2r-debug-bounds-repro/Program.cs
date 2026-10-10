using System.Reflection.PortableExecutable;
using ILCompiler.Reflection.ReadyToRun;

// Both widths are independently <= 32 bits, as in the actual v16 producer.
// 16 native bits + 15 IL bits + 2 source bits = 33 bits per record.
// SourceTypes: CALL_INSTRUCTION=16, STACK_EMPTY=2 (cordebuginfo.h, linked in PackedBounds).
bool wide = Check("33-bit record", PackedBounds.Encode((1U << 15, (1 << 14) - 3, 1)),
    [(1U << 15, (1 << 14) - 3, 16)]);
// Two five-bit records leave six zero padding bits, enough for a phantom third row.
bool padding = Check("padding", PackedBounds.Encode((1, 0, 2), (1, 0, 2)),
    [(1U, 0, 2), (2U, 0, 2)]);
// One five-bit record leaves only three padding bits: unchanged-reader control.
bool control = Check("control", PackedBounds.Encode((1, 0, 2)), [(1U, 0, 2)]);
return wide && padding && control ? 0 : 1;

static bool Check(string name, byte[] bytes, (uint native, int il, int source)[] expected)
{
    using var stream = new MemoryStream(bytes);
    var host = new RuntimeFunction
    {
        ReadyToRunReader = new()
        {
            ImageReader = new NativeReader(stream),
            Machine = Machine.Amd64,
            ReadyToRunHeader = new() { MajorVersion = 16 }
        }
    };
    var actual = new DebugInfo(host, 0).BoundsList
        .Select(row => (row.NativeOffset, unchecked((int)row.ILOffset), (int)row.SourceTypes)).ToArray();
    bool equal = expected.SequenceEqual(actual);
    Console.WriteLine($"{name}: {(equal ? "PASS" : "FAIL")}");
    Console.WriteLine($"  bytes:    {Convert.ToHexString(bytes)}");
    Console.WriteLine($"  expected: {string.Join(", ", expected)}");
    Console.WriteLine($"  actual:   {string.Join(", ", actual)}");
    return equal;
}
