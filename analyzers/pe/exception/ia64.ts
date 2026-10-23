import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { isValidFunctionRange } from "./function-range.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

interface Ia64TableState {
  result: PeExceptionDirectory;
  references: Set<number>;
  issues: Set<string>;
  previousBegin: number | undefined;
}

const recordUnwindReference = (state: Ia64TableState, reference: number,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  if (reference === 0) {
    state.issues.add("IA64 unwind information RVA is 0.");
  } else if (mappedRvaSize(rvaToOff, reference, 1, reader.size) !== 1) {
    state.issues.add("IA64 unwind information RVA could not be mapped.");
  } else state.references.add(reference);
};

const recordFunction = (state: Ia64TableState, view: DataView, offset: number,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  state.result.functionCount++;
  const begin = view.getUint32(offset, true);
  const length = view.getUint32(offset + 4, true) - begin;
  if (!isValidFunctionRange(begin, length, rvaToOff, reader.size)) {
    state.result.invalidEntryCount++;
    return;
  }
  if (state.previousBegin != null && begin < state.previousBegin) {
    state.issues.add("IA64 .pdata entries are not sorted by function start RVA.");
  }
  state.previousBegin = begin;
  state.result.beginRvas.push(begin);
  state.result.rangeLengths!.push(length);
  recordUnwindReference(state, view.getUint32(offset + 8, true), reader, rvaToOff);
};

// IMAGE_IA64_RUNTIME_FUNCTION_ENTRY has three DWORD RVAs even for PE32+.
// Its unwind payload is not AMD64 UNWIND_INFO; do not apply that decoder.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
// https://github.com/microsoft/win32metadata/blob/2f767671802301cf043c717d66bf004ed7863487/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
export const parseIa64ExceptionTable = async (reader: FileRangeReader,
  source: FileRangeReader, declaredSize: number, rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory> => {
  const result = createEmptyExceptionDirectory([], "ia64");
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 12) {
    result.issues.push("IA64 exception table size is smaller than one entry or invalid.");
    return result;
  }
  if (declaredSize % 12) result.issues.push("IA64 exception table size is not a multiple of its entry size (12 bytes).");
  result.rangeLengths = [];
  const state: Ia64TableState = { result, references: new Set(), issues: new Set(), previousBegin: undefined };
  for await (const view of readRuntimeFunctionChunks(source, Math.floor(declaredSize / 12), 12,
    "IA64 exception table is truncated; some entries are missing.", result.issues)) {
    for (let offset = 0; offset < view.byteLength; offset += 12) {
      recordFunction(state, view, offset, reader, rvaToOff);
    }
  }
  result.uniqueUnwindInfoCount = state.references.size;
  if (state.references.size) {
    state.issues.add("IA64 unwind payloads are not decoded; handler and chaining information is unavailable.");
  }
  result.issues.push(...state.issues);
  return result;
};
