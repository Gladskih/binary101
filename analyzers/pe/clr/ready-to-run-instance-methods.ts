import type { PeClrReadyToRunInstanceMethod } from "./ready-to-run-types.js";
import { NativeHashtableReader } from "../../native-aot/native-hashtable.js";
import { NativeFormatReader } from "../../native-aot/native-format-reader.js";
import { skipReadyToRunMethodSignature } from "./ready-to-run-method-signature.js";
import { decodeReadyToRunEntrypoint } from "./ready-to-run-entrypoint.js";

const cachedInstance = (
  bytes: Uint8Array, reader: NativeFormatReader, offset: number,
  cache: Map<number, PeClrReadyToRunInstanceMethod | Error>
): PeClrReadyToRunInstanceMethod | Error => {
  const cached = cache.get(offset);
  if (cached) return cached;
  try {
    const decoded = { signatureOffset: offset,
      ...decodeReadyToRunEntrypoint(reader, skipReadyToRunMethodSignature(bytes, offset)) };
    cache.set(offset, decoded);
    return decoded;
  } catch (error) {
    const failure = error instanceof Error ? error : new Error("instance decoding failed");
    cache.set(offset, failure);
    return failure;
  }
};

export const parseReadyToRunInstanceMethods = (
  bytes: Uint8Array, issues: Set<string>
): PeClrReadyToRunInstanceMethod[] => {
  const methods = new Set<PeClrReadyToRunInstanceMethod>();
  const warnings = new Set<string>();
  const cache = new Map<number, PeClrReadyToRunInstanceMethod | Error>();
  try {
    const table = new NativeHashtableReader(bytes);
    const reader = new NativeFormatReader(bytes);
    for (const entry of table.entries(warnings)) {
      const method = cachedInstance(bytes, reader, entry.offset, cache);
      if (method instanceof Error) warnings.add(method.message);
      else methods.add(method);
    }
  } catch (error) {
    warnings.add(error instanceof Error ? error.message : "instance table decoding failed");
  }
  for (const warning of warnings) issues.add(`InstanceMethodEntryPoints: ${warning}`);
  return [...methods];
};
