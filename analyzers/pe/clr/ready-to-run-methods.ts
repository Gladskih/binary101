import { NativeArrayReader } from "../../native-aot/native-array.js";
import { NativeFormatReader } from "../../native-aot/native-format-reader.js";
import type { PeClrReadyToRunMethod } from "./ready-to-run-types.js";
import { decodeReadyToRunEntrypoint } from "./ready-to-run-entrypoint.js";

// Entry encoding: low bit signals fixups, next bit a backward reference to shared fixups.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs#L1605
const cachedMethod = (
  reader: NativeFormatReader, offset: number,
  cache: Map<number, Omit<PeClrReadyToRunMethod, "methodRid"> | Error>
): Omit<PeClrReadyToRunMethod, "methodRid"> => {
  const cached = cache.get(offset);
  if (cached instanceof Error) throw cached;
  if (cached) return cached;
  try {
    const decoded = decodeReadyToRunEntrypoint(reader, offset);
    cache.set(offset, decoded);
    return decoded;
  } catch (error) {
    const failure = error instanceof Error ? error : new Error("decoding failed");
    cache.set(offset, failure);
    throw failure;
  }
};

export const parseReadyToRunMethods = (
  bytes: Uint8Array, issues: Set<string>
): PeClrReadyToRunMethod[] => {
  const array = new NativeArrayReader(bytes);
  const reader = new NativeFormatReader(bytes);
  const methods: PeClrReadyToRunMethod[] = [];
  const cache = new Map<number, Omit<PeClrReadyToRunMethod, "methodRid"> | Error>();
  for (let index = 0; index < array.count; index += 1) {
    try {
      const offset = array.at(index);
      if (offset !== null) methods.push({ methodRid: index + 1,
        ...cachedMethod(reader, offset, cache) });
    } catch (error) {
      issues.add(`MethodDefEntryPoints: ${error instanceof Error ? error.message : "decoding failed"}`);
    }
  }
  return methods;
};
