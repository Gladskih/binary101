import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { createArmntUnwindInfoReader, type ArmntUnwindInfo } from "./armnt-unwind-info.js";
import { isValidFunctionRange } from "./function-range.js";
import type { ArmntPackedStatistics } from "./armnt-packed-types.js";
import { createArmntPackedStatistics, recordArmntPackedStatistics } from "./armnt-packed-statistics.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

// ARM .pdata records are two DWORDs. A Thumb address has its low bit set.
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling#pdata-records
const ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE = 8;

interface ArmntExceptionState {
  functionCount: number;
  beginRvas: number[];
  rangeLengths: number[];
  handlerRvas: Set<number>;
  uniqueUnwindWords: Set<number>;
  handlerUnwindInfoCount: number;
  invalidEntryCount: number;
  packed: ArmntPackedStatistics | null;
  fragmentEntryCount: number;
  previousBegin: number | null;
  reportedUnsortedEntries: boolean;
}

const createState = (): ArmntExceptionState => ({
  functionCount: 0, beginRvas: [], rangeLengths: [], handlerRvas: new Set(),
  uniqueUnwindWords: new Set(), handlerUnwindInfoCount: 0, invalidEntryCount: 0,
  packed: null, fragmentEntryCount: 0, previousBegin: null, reportedUnsortedEntries: false
});

const recordMetadata = (word: number, info: ArmntUnwindInfo, state: ArmntExceptionState): void => {
  state.uniqueUnwindWords.add(word);
  if ((word & 3) !== 0) {
    state.packed ??= createArmntPackedStatistics();
    recordArmntPackedStatistics(state.packed, word);
  }
  if (info.fragment) state.fragmentEntryCount += 1;
  if (info.hasHandler) state.handlerUnwindInfoCount += 1;
  // LLVM's ARM SEH emitter also stores Thumb state in the handler pointer.
  // https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/test/MC/ARM/seh.s
  const handlerRva = info.handlerRva == null ? 0 : info.handlerRva - (info.handlerRva & 1);
  if (handlerRva) state.handlerRvas.add(handlerRva);
};

const processEntry = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  begin: number, word: number, state: ArmntExceptionState, issues: string[],
  readUnwind: ReturnType<typeof createArmntUnwindInfoReader>): Promise<void> => {
  state.functionCount += 1;
  const info = await readUnwind(word, issues);
  if (info) recordMetadata(word, info, state);
  const beginRva = begin - (begin & 1);
  if (!info || !isValidFunctionRange(beginRva, info.functionLengthBytes, rvaToOff, reader.size)) {
    state.invalidEntryCount += 1;
    return;
  }
  if (state.previousBegin != null && beginRva < state.previousBegin && !state.reportedUnsortedEntries) {
    issues.push("ARMNT .pdata entries are not sorted by function start RVA.");
    state.reportedUnsortedEntries = true;
  }
  state.previousBegin = beginRva;
  state.beginRvas.push(beginRva);
  state.rangeLengths.push(info.functionLengthBytes);
};

export const parseArmntExceptionDirectory = async (reader: FileRangeReader,
  dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset): Promise<PeExceptionDirectory | null> => {
  const directory = dataDirs.find(entry => entry.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  if (directory.rva === 0) return createEmptyExceptionDirectory([
    "Exception directory has a non-zero size but RVA is 0."], "armnt");
  const offset = rvaToOff(directory.rva);
  if (offset == null) return createEmptyExceptionDirectory([
    "Exception directory RVA could not be mapped to a file offset."], "armnt");
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) return createEmptyExceptionDirectory([
    "Exception directory location is outside the file."], "armnt");
  return parseArmntExceptionTable(reader,
    createRvaRangeReader(reader, rvaToOff, directory.rva, directory.size), directory.size, rvaToOff);
};

export const parseArmntExceptionTable = async (reader: FileRangeReader, source: FileRangeReader,
  declaredSize: number, rvaToOff: RvaToOffset): Promise<PeExceptionDirectory> => {
  if (declaredSize < ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE) return createEmptyExceptionDirectory([
    "Exception directory size is smaller than one ARMNT .pdata entry (8 bytes)."], "armnt");
  const issues: string[] = [];
  if (declaredSize % ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of ARMNT .pdata entry size (8 bytes).");
  }
  const state = createState();
  const readUnwind = createArmntUnwindInfoReader(reader, rvaToOff);
  for await (const view of readRuntimeFunctionChunks(source,
    Math.floor(declaredSize / ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE), ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE,
    "Exception directory is truncated; some ARMNT .pdata entries are missing.", issues)) {
    for (let offset = 0; offset < view.byteLength; offset += ARMNT_RUNTIME_FUNCTION_ENTRY_SIZE) {
      await processEntry(reader, rvaToOff, view.getUint32(offset, true), view.getUint32(offset + 4, true),
        state, issues, readUnwind);
    }
  }
  if (state.functionCount === 0) {
    issues.push("Exception directory does not contain a complete ARMNT .pdata entry.");
    return createEmptyExceptionDirectory(issues, "armnt");
  }
  return { functionCount: state.functionCount, beginRvas: state.beginRvas, rangeLengths: state.rangeLengths,
    handlerRvas: [...state.handlerRvas], uniqueUnwindInfoCount: state.uniqueUnwindWords.size,
    handlerUnwindInfoCount: state.handlerUnwindInfoCount, chainedUnwindInfoCount: 0,
    ...(state.packed ? { armntPacked: state.packed } : {}), fragmentEntryCount: state.fragmentEntryCount,
    invalidEntryCount: state.invalidEntryCount, issues, format: "armnt" };
};
