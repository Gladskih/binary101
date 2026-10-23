import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { isValidFunctionRange } from "./function-range.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

export type NtRiscExceptionFormat = "nt-risc32" | "nt-risc64";
interface NtRiscState {
  result: PeExceptionDirectory;
  handlers: Set<number>;
  issues: Set<string>;
  previousBegin: number | undefined;
}

const vaToRva = (value: bigint, imageBase: bigint): number | null =>
  value < imageBase || value - imageBase > 0xffffffffn ? null : Number(value - imageBase);

const mappedVa = (value: bigint, imageBase: bigint, reader: FileRangeReader,
  rvaToOff: RvaToOffset): number | null => {
  const rva = vaToRva(value, imageBase);
  return rva != null && mappedRvaSize(rvaToOff, rva, 1, reader.size) === 1 ? rva : null;
};

const recordProlog = (state: NtRiscState, begin: bigint, end: bigint, prolog: bigint): boolean => {
  // Binutils preserves the low handler/prolog bits as EM metadata, not addresses.
  // https://gnu.googlesource.com/binutils-gdb/+/refs/tags/binutils-2_44/bfd/peXXigen.c#1932
  if (prolog & 3n) state.issues.add("Tagged NT RISC prolog metadata is not decoded.");
  const location = prolog & ~3n;
  if (location < begin || location > end) {
    state.issues.add("NT RISC prolog location is outside its function; indirect prolog metadata is not decoded.");
    return false;
  }
  const length = Number(location - begin);
  const statistics = state.result.riscPrologs ??=
    { count: 0, empty: 0, minimumBytes: length, maximumBytes: length };
  statistics.count++;
  statistics.empty += Number(length === 0);
  statistics.minimumBytes = Math.min(statistics.minimumBytes, length);
  statistics.maximumBytes = Math.max(statistics.maximumBytes, length);
  return true;
};

const recordHandler = (state: NtRiscState, handler: bigint, data: bigint, imageBase: bigint,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  if (handler & 3n) state.issues.add("Tagged NT RISC handler metadata is not decoded.");
  if (handler & ~3n) {
    state.result.handlerUnwindInfoCount++;
    const rva = mappedVa(handler & ~3n, imageBase, reader, rvaToOff);
    if (rva == null) state.issues.add("NT RISC exception handler VA could not be mapped.");
    else state.handlers.add(rva);
  }
  if (data && mappedVa(data, imageBase, reader, rvaToOff) == null) {
    state.issues.add("NT RISC handler data VA could not be mapped.");
  }
};

const recordFunction = (state: NtRiscState, fields: readonly bigint[], imageBase: bigint,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  state.result.functionCount++;
  const begin = vaToRva(fields[0]!, imageBase);
  const end = vaToRva(fields[1]!, imageBase);
  if (begin == null || end == null || !isValidFunctionRange(begin, end - begin, rvaToOff, reader.size)) {
    state.result.invalidEntryCount++;
    return;
  }
  if (state.previousBegin != null && begin < state.previousBegin) {
    state.issues.add("NT RISC .pdata entries are not sorted by function start VA.");
  }
  state.previousBegin = begin;
  state.result.beginRvas.push(begin);
  state.result.rangeLengths!.push(end - begin);
  // A secondary row can repurpose HandlerData (dumpbin displays its low bits
  // as a type). Do not interpret those fields as primary handler VAs.
  if (recordProlog(state, fields[0]!, fields[1]!, fields[4]!)) {
    recordHandler(state, fields[2]!, fields[3]!, imageBase, reader, rvaToOff);
  }
};

const readFields = (view: DataView, offset: number, width: number): bigint[] =>
  Array.from({ length: 5 }, (_, index) => width === 8
    ? view.getBigUint64(offset + index * width, true) : BigInt(view.getUint32(offset + index * width, true)));

const isValidImageBase = (imageBase: bigint | undefined): imageBase is bigint =>
  imageBase != null && imageBase >= 0n && imageBase <= 0xffffffffffffffffn;

// Microsoft PE .pdata: MIPS uses five DWORD VAs. Windows SDK winnt.h defines
// the same layout for Alpha, and five ULONGLONG VAs for Alpha64.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
// https://github.com/microsoft/win32metadata/blob/2f767671802301cf043c717d66bf004ed7863487/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
export const parseNtRiscExceptionTable = async (
  reader: FileRangeReader, source: FileRangeReader, declaredSize: number,
  rvaToOff: RvaToOffset, format: NtRiscExceptionFormat, imageBase?: bigint
): Promise<PeExceptionDirectory> => {
  const width = format === "nt-risc64" ? 8 : 4;
  const result = createEmptyExceptionDirectory([], format);
  if (!isValidImageBase(imageBase)) {
    result.issues.push("NT RISC absolute VAs require a valid PE ImageBase.");
    return result;
  }
  if (!Number.isSafeInteger(declaredSize) || declaredSize < width * 5) {
    result.issues.push("NT RISC exception table size is smaller than one entry or invalid.");
    return result;
  }
  if (declaredSize % (width * 5)) result.issues.push("NT RISC exception table size is not a multiple of its entry size.");
  result.rangeLengths = [];
  const state: NtRiscState = { result, handlers: new Set(), issues: new Set(), previousBegin: undefined };
  for await (const view of readRuntimeFunctionChunks(source, Math.floor(declaredSize / (width * 5)), width * 5,
    "NT RISC exception table is truncated; some entries are missing.", result.issues)) {
    for (let offset = 0; offset < view.byteLength; offset += width * 5) {
      recordFunction(state, readFields(view, offset, width), imageBase, reader, rvaToOff);
    }
  }
  result.handlerRvas = [...state.handlers];
  // Each physical row contains its own inline description, with no .xdata pointer.
  result.uniqueUnwindInfoCount = result.functionCount;
  result.issues.push(...state.issues);
  return result;
};
