import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { isValidFunctionRange } from "./function-range.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory, type PeCeExceptionStatistics } from "./types.js";

interface CeExceptionState {
  result: PeExceptionDirectory;
  handlers: Set<number>;
  issues: Set<string>;
  imageBase: bigint;
  machine: number;
  previousBegin: number | undefined;
}

const statisticsForEntry = (state: CeExceptionState, word: number): PeCeExceptionStatistics => {
  const statistics = state.result.ceCompressed ??= { instruction16Count: 0, instruction32Count: 0,
    extendedEntryCount: 0, handlerDataCount: 0 };
  statistics.instruction32Count += word >>> 30 & 1;
  statistics.instruction16Count += 1 - (word >>> 30 & 1);
  state.result.functionCount++;
  state.result.handlerUnwindInfoCount += word >>> 31;
  return statistics;
};

const recordRange = (state: CeExceptionState, beginVa: number, length: number,
  reader: FileRangeReader, rvaToOff: RvaToOffset): number | null => {
  // CE PDATA documentation guarantees four-byte alignment of associated functions.
  // https://learn.microsoft.com/en-us/previous-versions/windows/embedded/aa448751(v=msdn.10)
  if (beginVa % 4) state.issues.add("CE function start is not four-byte aligned.");
  const begin = Number(BigInt(beginVa) - state.imageBase);
  if (beginVa % 4 || !isValidFunctionRange(begin, length, rvaToOff, reader.size)) {
    state.result.invalidEntryCount++;
    return null;
  }
  if (state.previousBegin != null && begin < state.previousBegin) {
    state.issues.add("CE .pdata entries are not sorted by function start VA.");
  }
  state.previousBegin = begin;
  state.result.beginRvas.push(begin);
  state.result.rangeLengths!.push(length);
  return begin;
};

const recordProlog = (statistics: PeCeExceptionStatistics, prolog: number, instructions: number,
  width: number, issues: Set<string>): void => {
  if (prolog > instructions) {
    issues.add("CE prolog instruction count exceeds the function instruction count.");
    return;
  }
  const length = prolog * width;
  const prologs = statistics.prologs ??= { count: 0, empty: 0, minimumBytes: length, maximumBytes: length };
  prologs.count++;
  prologs.empty += Number(prolog === 0);
  prologs.minimumBytes = Math.min(prologs.minimumBytes, length);
  prologs.maximumBytes = Math.max(prologs.maximumBytes, length);
};

const mappedPointer = (value: number, state: CeExceptionState, reader: FileRangeReader,
  rvaToOff: RvaToOffset): number | null => {
  // Both the wire VA and the validated CE ImageBase are unsigned 32-bit values.
  const rva = Number(BigInt(value) - state.imageBase);
  return mappedRvaSize(rvaToOff, rva, 1, reader.size) === 1 ? rva : null;
};

const recordHandlerPointer = (handler: number, state: CeExceptionState,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  if (!handler) return;
  // Arm code-pointer bit 0 selects Thumb; it is not part of the code address.
  // https://github.com/ARM-software/abi-aa/blob/2025Q1/aapcs32/aapcs32.rst#fundamental-data-types
  const codeAddress = [0x1c0, 0x1c2].includes(state.machine) ? handler - (handler & 1) : handler;
  if (codeAddress & 1) {
    state.issues.add("CE non-Arm exception handler VA is not instruction-aligned.");
    return;
  }
  const rva = mappedPointer(codeAddress, state, reader, rvaToOff);
  if (rva == null) state.issues.add("CE exception handler VA could not be mapped.");
  else state.handlers.add(rva);
};

const recordPointers = (state: CeExceptionState, fields: DataView, statistics: PeCeExceptionStatistics,
  reader: FileRangeReader, rvaToOff: RvaToOffset): void => {
  recordHandlerPointer(fields.getUint32(0, true), state, reader, rvaToOff);
  const data = fields.getUint32(4, true);
  if (!data) return;
  statistics.handlerDataCount++;
  if (mappedPointer(data, state, reader, rvaToOff) == null) state.issues.add("CE handler data VA could not be mapped.");
};

const readHandler = async (state: CeExceptionState, begin: number, statistics: PeCeExceptionStatistics,
  reader: FileRangeReader, rvaToOff: RvaToOffset): Promise<void> => {
  // PDATA_EH consists of two VA pointers immediately before the function.
  // https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms940765(v=msdn.10)
  if (begin < 8) {
    state.issues.add("CE PDATA_EH would start before the image.");
    return;
  }
  const fields = await readMappedRvaPrefix(reader, begin - 8, 8, rvaToOff);
  if (fields.byteLength !== 8) {
    state.issues.add("CE PDATA_EH is truncated or not fully mapped.");
    return;
  }
  recordPointers(state, fields, statistics, reader, rvaToOff);
};

const recordEntry = async (state: CeExceptionState, beginVa: number, word: number,
  reader: FileRangeReader, rvaToOff: RvaToOffset): Promise<void> => {
  const statistics = statisticsForEntry(state, word);
  const instructions = word >>> 8 & 0x3fffff;
  if (!instructions) {
    // The public CE documentation mentions an extension but does not specify
    // the extended length record's layout. Retain its presence without guessing.
    statistics.extendedEntryCount++;
    state.result.invalidEntryCount++;
    state.issues.add("CE extended function-length metadata is not decoded.");
    return;
  }
  const width = word & 0x40000000 ? 4 : 2;
  const begin = recordRange(state, beginVa, instructions * width, reader, rvaToOff);
  if (begin == null) return;
  recordProlog(statistics, word & 255, instructions, width, state.issues);
  if (word >>> 31) await readHandler(state, begin, statistics, reader, rvaToOff);
};

const isCeImageBase = (imageBase: bigint | undefined): imageBase is bigint =>
  imageBase != null && imageBase >= 0n && imageBase <= 0xffffffffn;

// Windows CE compressed .pdata consists of two DWORDs, including an absolute
// function VA. ARMNT's newer RVA/packed-unwind format is a different ABI.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
export const parseCeExceptionTable = async (reader: FileRangeReader, source: FileRangeReader,
  declaredSize: number, rvaToOff: RvaToOffset, imageBase?: bigint, machine = 0x1c0
): Promise<PeExceptionDirectory> => {
  const result = createEmptyExceptionDirectory([], "ce");
  if (!isCeImageBase(imageBase)) {
    result.issues.push("CE absolute VAs require a valid 32-bit PE ImageBase.");
    return result;
  }
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 8) {
    result.issues.push("CE exception table size is smaller than one entry or invalid.");
    return result;
  }
  if (declaredSize % 8) result.issues.push("CE exception table size is not a multiple of 8 bytes.");
  result.rangeLengths = [];
  const state: CeExceptionState = { result, handlers: new Set(), issues: new Set(), imageBase, machine,
    previousBegin: undefined };
  for await (const view of readRuntimeFunctionChunks(source, Math.floor(declaredSize / 8), 8,
    "CE exception table is truncated; some entries are missing.", result.issues)) {
    for (let offset = 0; offset < view.byteLength; offset += 8) {
      await recordEntry(state, view.getUint32(offset, true), view.getUint32(offset + 4, true), reader, rvaToOff);
    }
  }
  result.handlerRvas = [...state.handlers];
  result.uniqueUnwindInfoCount = result.functionCount;
  result.issues.push(...state.issues);
  return result;
};
