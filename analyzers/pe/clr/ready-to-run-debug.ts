import { NativeArrayReader } from "../../native-aot/native-array.js";
import { NativeFormatReader } from "../../native-aot/native-format-reader.js";
import { NibbleReader } from "../../native-aot/nibble-reader.js";
import { readDebugBounds } from "./ready-to-run-debug-bounds.js";
import { readDebugVariables } from "./ready-to-run-debug-variables.js";
import type { ReadyToRunDebugMethod } from "./ready-to-run-debug-types.js";

type DebugPayload = Pick<ReadyToRunDebugMethod, "bounds" | "variables">;

const readPayload = (bytes: Uint8Array, offset: number, version: number,
  machine: number | undefined, warnings: Set<string>): DebugPayload => {
  const header = new NibbleReader(bytes.subarray(offset));
  const boundsSize = header.unsigned();
  const variablesSize = header.unsigned();
  const boundsStart = offset + header.byteOffset;
  const variablesStart = boundsStart + boundsSize;
  if (variablesStart + variablesSize > bytes.length) warnings.add("DebugInfo payload is truncated.");
  return {
    bounds: boundsSize ? readDebugBounds(bytes.subarray(boundsStart, variablesStart), version, warnings) : [],
    variables: variablesSize ? readDebugVariables(bytes.subarray(variablesStart,
      variablesStart + variablesSize), machine, warnings) : []
  };
};

// DebugInfo NativeArray entries are zero + inline payload, or a backwards byte distance
// from the start of the encoded distance (not its end). The payloads are shared, not recursive.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/DebugInfo.cs
export const parseReadyToRunDebug = (bytes: Uint8Array, majorVersion: number,
  machine: number | undefined, warnings: Set<string>): ReadyToRunDebugMethod[] => {
  const methods: ReadyToRunDebugMethod[] = [];
  const payloads = new Map<number, DebugPayload>();
  try {
    const array = new NativeArrayReader(bytes);
    const reader = new NativeFormatReader(bytes);
    for (let runtimeFunctionIndex = 0; runtimeFunctionIndex < array.count; runtimeFunctionIndex++) {
      try {
        const entry = array.at(runtimeFunctionIndex);
        if (entry === null) continue;
        const lookback = reader.unsigned(entry);
        const offset = lookback.value ? entry - lookback.value : lookback.nextOffset;
        if (offset < 0) throw new Error("DebugInfo lookback is outside the section.");
        const payload = payloads.get(offset) ?? readPayload(bytes, offset, majorVersion, machine, warnings);
        payloads.set(offset, payload);
        methods.push({ runtimeFunctionIndex, ...payload });
      } catch (error) { warnings.add(`DebugInfo: ${(error as Error).message}`); }
    }
  } catch (error) { warnings.add(`DebugInfo: ${(error as Error).message}`); }
  return methods;
};
