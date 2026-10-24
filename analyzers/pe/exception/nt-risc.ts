import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { isValidFunctionRange } from "./function-range.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";
import { recordAlphaProlog, finishAlphaPrologs, type AlphaPrologState } from "./alpha-prologs.js";

export type NtRiscExceptionFormat = "nt-risc32" | "nt-risc64";
interface NtRiscState {
  result: PeExceptionDirectory;
  handlers: Set<number>;
  issues: Set<string>;
  previousBegin: number | undefined;
  machine: number | undefined;
  alpha?: AlphaPrologState;
  alphaSecondaryHandlers?: (readonly bigint[])[];
}

const vaToRva = (value: bigint, imageBase: bigint): number | null =>
  value < imageBase || value - imageBase > 0xffffffffn ? null : Number(value - imageBase);

const mappedVa = (value: bigint, imageBase: bigint, reader: FileRangeReader,
  rvaToOff: RvaToOffset): number | null => {
  const rva = vaToRva(value, imageBase);
  return rva != null && mappedRvaSize(rvaToOff, rva, 1, reader.size) === 1 ? rva : null;
};

const recordProlog = (state: NtRiscState, begin: bigint, end: bigint, prolog: bigint): boolean => {
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

const recordPowerPcCodeSignificance = (state: NtRiscState, handler: bigint, data: bigint): boolean => {
  if (state.result.format !== "nt-risc32" || ![0x1f0, 0x1f1].includes(state.machine ?? 0) ||
      (handler & ~3n) !== 0n || data < 1n || data > 3n) return false;
  // GNU peXXigen.c interprets these codes only when the untagged handler is null.
  // dlltool.c emits HandlerData=3 for glue, confirming that this is not a VA.
  // https://gnu.googlesource.com/binutils-gdb/+/refs/tags/binutils-2_34/bfd/peXXigen.c#1988
  // https://gnu.googlesource.com/binutils-gdb/+/refs/tags/binutils-2_34/binutils/dlltool.c#2855
  const counts = state.result.powerPcCodeSignificance ??= [0, 0, 0];
  const index = Number(data) - 1;
  counts[index] = counts[index]! + 1;
  return true;
};

const recordHandler = (state: NtRiscState, handler: bigint, data: bigint, imageBase: bigint,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  if (handler & 2n) state.issues.add("Unknown NT RISC handler address tag bit 1 is set.");
  if (handler & ~3n) {
    state.result.handlerUnwindInfoCount++;
    const rva = mappedVa(handler & ~3n, imageBase, reader, rvaToOff);
    if (rva == null) state.issues.add("NT RISC exception handler VA could not be mapped.");
    else state.handlers.add(rva);
  }
  if (recordPowerPcCodeSignificance(state, handler, data)) return;
  if (data && mappedVa(data, imageBase, reader, rvaToOff) == null) {
    state.issues.add("NT RISC handler data VA could not be mapped.");
  }
};

const recordExceptionMode = (state: NtRiscState, fields: readonly bigint[]): void => {
  // GNU's public PE decoder combines handler bit 0 and prolog bits 0-1 as EM.
  // Keep the numeric mode: named meanings of the third bit are not established.
  // https://gnu.googlesource.com/binutils-gdb/+/refs/tags/binutils-2_44/bfd/peXXigen.c#1928
  if (state.result.format !== "nt-risc32") {
    if ((fields[2]! & 1n) || (fields[4]! & 3n)) state.issues.add("Tagged Alpha64 exception metadata is not decoded.");
    return;
  }
  state.result.riscExceptionModes ??= Array<number>(8).fill(0);
  const mode = Number(((fields[2]! & 1n) << 2n) | (fields[4]! & 3n));
  state.result.riscExceptionModes[mode] = state.result.riscExceptionModes[mode]! + 1;
};

const recordInlineMetadata = (state: NtRiscState, fields: readonly bigint[], imageBase: bigint,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  recordExceptionMode(state, fields);
  if (state.alpha) {
    const location = recordAlphaProlog(state.alpha, fields[0]!, fields[1]!, fields[4]! & ~3n);
    if (location != null) {
      recordProlog(state, fields[0]!, fields[1]!, location);
      recordHandler(state, fields[2]!, fields[3]!, imageBase, reader, rvaToOff);
    } else (state.alphaSecondaryHandlers ??= []).push(fields);
  } else if (recordProlog(state, fields[0]!, fields[1]!, fields[4]!)) {
    recordHandler(state, fields[2]!, fields[3]!, imageBase, reader, rvaToOff);
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
  recordInlineMetadata(state, fields, imageBase, reader, rvaToOff);
};

const readFields = (view: DataView, offset: number, width: number): bigint[] =>
  Array.from({ length: 5 }, (_, index) => width === 8
    ? view.getBigUint64(offset + index * width, true) : BigInt(view.getUint32(offset + index * width, true)));

const isValidImageBase = (imageBase: bigint | undefined): imageBase is bigint =>
  imageBase != null && imageBase >= 0n && imageBase <= 0xffffffffffffffffn;

const finishInlineMetadata = (state: NtRiscState, imageBase: bigint, reader: FileRangeReader,
  rvaToOff: RvaToOffset): void => {
  if (state.alpha) {
    state.result.alphaPrologs = finishAlphaPrologs(state.alpha);
    if (state.result.alphaPrologs.unresolvedSecondaryRanges) state.issues.add(
      "Alpha secondary ranges do not match known procedure-start references; other secondary ABIs are not decoded.");
    // Secondary fields may belong to another ABI. Interpret handler VAs only
    // after validating the early Alpha procedure-start reference against a primary row.
    for (const fields of state.alphaSecondaryHandlers ?? []) {
      if (state.alpha.primaryBegins.has(fields[4]! & ~3n)) {
        recordHandler(state, fields[2]!, fields[3]!, imageBase, reader, rvaToOff);
      }
    }
  }
  state.result.handlerRvas = [...state.handlers];
  // Each physical row contains its own inline description, with no .xdata pointer.
  state.result.uniqueUnwindInfoCount = state.result.functionCount;
  state.result.issues.push(...state.issues);
};

// Microsoft PE .pdata: MIPS uses five DWORD VAs. Windows SDK winnt.h defines
// the same layout for Alpha, and five ULONGLONG VAs for Alpha64.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
// https://github.com/microsoft/win32metadata/blob/2f767671802301cf043c717d66bf004ed7863487/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
export const parseNtRiscExceptionTable = async (
  reader: FileRangeReader, source: FileRangeReader, declaredSize: number,
  rvaToOff: RvaToOffset, format: NtRiscExceptionFormat, imageBase?: bigint, machine?: number
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
  const state: NtRiscState = { result, handlers: new Set(), issues: new Set(), previousBegin: undefined, machine };
  if (machine === 0x184) state.alpha = { primaryBegins: new Set(), secondaryBegins: [] };
  for await (const view of readRuntimeFunctionChunks(source, Math.floor(declaredSize / (width * 5)), width * 5,
    "NT RISC exception table is truncated; some entries are missing.", result.issues)) {
    for (let offset = 0; offset < view.byteLength; offset += width * 5) {
      recordFunction(state, readFields(view, offset, width), imageBase, reader, rvaToOff);
    }
  }
  finishInlineMetadata(state, imageBase, reader, rvaToOff);
  return result;
};
