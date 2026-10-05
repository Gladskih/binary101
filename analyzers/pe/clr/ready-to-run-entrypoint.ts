import type { NativeFormatReader } from "../../native-aot/native-format-reader.js";

// Shared by MethodDefEntryPoints and InstanceMethodEntryPoints.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
export const decodeReadyToRunEntrypoint = (
  reader: NativeFormatReader, offset: number
): { runtimeFunctionIndex: number; fixupOffset: number | null } => {
  const entry = reader.unsigned(offset);
  if ((entry.value & 1) === 0) {
    return { runtimeFunctionIndex: entry.value >>> 1, fixupOffset: null };
  }
  const fixupOffset = (entry.value & 2) === 0 ? entry.nextOffset
    : entry.nextOffset - reader.unsigned(entry.nextOffset).value;
  if (fixupOffset < 0 || fixupOffset >= reader.size) {
    throw new Error("Method fixup offset is outside the section.");
  }
  return { runtimeFunctionIndex: entry.value >>> 2, fixupOffset };
};
