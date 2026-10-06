#nullable enable
using Internal.Runtime;

// Decode command bytes with the unmodified runtime DehydratedDataCommand implementation.
sealed class NativeMapHydration(NativeMapImage image, NativeMapReference.Blob? stream)
{
    readonly Dictionary<long, long> pointers = new();
    readonly List<(long address, int size, long? source)> runs = new();
    bool loaded;

    unsafe void Load()
    {
        loaded = true;
        if (stream == null || stream.bytes.Length == 0) return;
        long destination = stream.rva + BitConverter.ToInt32(stream.bytes);
        fixed (byte* bytes = stream.bytes)
        {
            byte* current = bytes + 4;
            while (current < bytes + stream.bytes.Length)
            {
                int extra = Math.Max(0, (*current >> 3) - 28);
                if (current + 1 + extra > bytes + stream.bytes.Length) throw new EndOfStreamException();
                current = DehydratedDataCommand.Decode(current, out int command, out int payload);
                if (command is 0 or 1)
                {
                    if (command == 0 && current + payload > bytes + stream.bytes.Length)
                        throw new EndOfStreamException();
                    runs.Add((destination, payload, command == 0 ? stream.rva + (current - bytes) : null));
                    destination += payload;
                    if (command == 0) current += payload;
                }
                else if (command is 2 or 3)
                {
                    long target = image.Relative(stream.rva + stream.bytes.Length + payload * 4L);
                    if (command == 3) pointers.Add(destination, target);
                    destination += command == 3 ? image.PointerSize : 4;
                }
                else if (command is 4 or 5)
                {
                    if (current + payload * 4L > bytes + stream.bytes.Length) throw new EndOfStreamException();
                    for (int index = 0; index < payload; index++, current += 4)
                    {
                        if (command == 5) pointers.Add(destination, stream.rva + (current - bytes) + *(int*)current);
                        destination += command == 5 ? image.PointerSize : 4;
                    }
                }
                else throw new InvalidDataException("Unknown hydration command");
            }
        }
    }

    public long? Pointer(long address)
    {
        if (!loaded) Load();
        if (pointers.TryGetValue(address, out long target)) return target;
        foreach (var run in runs)
            if (address >= run.address && address + image.PointerSize <= run.address + run.size)
                return run.source.HasValue ? image.Absolute(run.source.Value + address - run.address) : null;
        return image.Absolute(address);
    }

    public long? Function(long? target)
    {
        if (!target.HasValue) return null;
        if ((target.Value & 2) != 0) target = Pointer(target.Value - 2);
        if (!target.HasValue || !image.Executable(target.Value)) throw new InvalidDataException("Not executable");
        return target;
    }
}
