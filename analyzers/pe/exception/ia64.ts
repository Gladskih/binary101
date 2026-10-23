import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { isValidFunctionRange } from "./function-range.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory, type PeIa64UnwindStatistics } from "./types.js";
import { parseIa64UnwindInfo, type Ia64UnwindInfo } from "./ia64-unwind.js";

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

const mergeDescriptorStatistics = (statistics: PeIa64UnwindStatistics, info: Ia64UnwindInfo): void => {
  for (const [kind, count] of Object.entries(info.counts)) {
    statistics.descriptorCounts[kind] = (statistics.descriptorCounts[kind] ?? 0) + count;
  }
  if (info.maximumFixedStackBytes != null) statistics.maximumFixedStackBytes =
    Math.max(statistics.maximumFixedStackBytes ?? 0, info.maximumFixedStackBytes);
};

const readUnwindReferences = async (state: Ia64TableState, reader: FileRangeReader,
  rvaToOff: RvaToOffset): Promise<void> => {
  if (!state.references.size) return;
  const versions = new Map<number, number>();
  const statistics: PeIa64UnwindStatistics = { versions: [], descriptorCounts: {},
    exceptionHandlerCount: 0, unwindHandlerCount: 0 };
  state.result.ia64Unwind = statistics;
  for (const reference of state.references) {
    const info = await parseIa64UnwindInfo(reader, rvaToOff, reference);
    if (info.version != null) versions.set(info.version, (versions.get(info.version) ?? 0) + 1);
    if (info.version === 3) {
      state.result.handlerUnwindInfoCount += Number((info.flags! & 3) !== 0);
      statistics.exceptionHandlerCount += Number((info.flags! & 1) !== 0);
      statistics.unwindHandlerCount += Number((info.flags! & 2) !== 0);
    }
    mergeDescriptorStatistics(statistics, info);
    for (const issue of info.issues) state.issues.add(issue);
  }
  statistics.versions = [...versions].map(([version, count]) => ({ version, count }));
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
  await readUnwindReferences(state, reader, rvaToOff);
  result.issues.push(...state.issues);
  return result;
};
