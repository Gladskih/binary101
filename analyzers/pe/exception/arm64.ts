"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { isMappedFunctionBegin, isValidFunctionRange } from "./function-range.js";
import { createArm64ExceptionState, recordArm64HandlerRva, type Arm64ExceptionState } from "./arm64-state.js";
import { createArm64UnwindInfoReader, type Arm64UnwindInfo } from "./arm64-unwind-info.js";
import { readRuntimeFunctionChunks } from "./runtime-function-chunks.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";
import { recordArm64PackedStatistics } from "./arm64-packed-statistics.js";
import { recordArm64UnwindStatistics } from "./arm64-unwind-statistics.js";

// Microsoft ARM64 exception-handling docs, .pdata records are two DWORDs.
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#pdata-records
const ARM64_RUNTIME_FUNCTION_ENTRY_SIZE = 8;

const recordUnwindInfo = (info: Arm64UnwindInfo, word: number, state: Arm64ExceptionState): void => {
  recordArm64PackedStatistics(state.packed, word);
  if (info.unwind && !state.seenXdata.has(info.unwind)) {
    state.seenXdata.add(info.unwind);
    recordArm64UnwindStatistics(state.unwind, info.unwind);
  }
  state.uniqueUnwindInfos.add(info.key);
  if (info.version != null && info.version !== 0) state.unexpectedXdataVersionCount++;
  if (info.hasHandler) state.handlerUnwindInfoCount++;
  if (info.chained) state.chainedUnwindInfoCount++;
  recordArm64HandlerRva(state, info.handlerRva);
};

const processArm64RuntimeFunction = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  beginRva: number,
  unwindWord: number,
  issues: string[],
  state: Arm64ExceptionState,
  readUnwindInfo: ReturnType<typeof createArm64UnwindInfoReader>
): Promise<void> => {
  state.functionCount += 1;
  const unwindInfo = await readUnwindInfo(unwindWord, issues);
  if (!unwindInfo) {
    state.invalidEntryCount++;
    return;
  }
  recordUnwindInfo(unwindInfo, unwindWord, state);
  const valid = unwindInfo.chained ? isMappedFunctionBegin(beginRva, rvaToOff, reader.size)
    : isValidFunctionRange(beginRva, unwindInfo.functionLengthBytes, rvaToOff, reader.size);
  if (!valid) {
    state.invalidEntryCount += 1;
    return;
  }
  if (state.previousBegin != null && beginRva < state.previousBegin && !state.reportedUnsortedEntries) {
    issues.push("ARM64 .pdata entries are not sorted by function start RVA.");
    state.reportedUnsortedEntries = true;
  }
  if (unwindInfo.languageHandler && !unwindInfo.chained) state.languageHandlers.push({
    ...unwindInfo.languageHandler,
    functionRanges: [{ begin: beginRva, end: beginRva + unwindInfo.functionLengthBytes }]
  });
  state.previousBegin = beginRva;
  state.beginRvas.push(beginRva);
  // Chained entries validate only the start; their target's length is not this range's length.
  if (!unwindInfo.chained) state.rangeLengths.push(unwindInfo.functionLengthBytes);
};

export async function parseArm64ExceptionDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> {
  const dir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!dir || (dir.rva === 0 && dir.size === 0)) {
    return null;
  }
  if (dir.rva === 0) {
    return createEmptyExceptionDirectory([
      "Exception directory has a non-zero size but RVA is 0."
    ], "arm64");
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyExceptionDirectory([
      "Exception directory RVA could not be mapped to a file offset."
    ], "arm64");
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExceptionDirectory([
      "Exception directory location is outside the file."
    ], "arm64");
  }
  return parseArm64ExceptionTable(reader,
    createRvaRangeReader(reader, rvaToOff, dir.rva, dir.size), dir.size, rvaToOff, dir.rva);
}

/** Decode a bounded .pdata source while resolving its addresses against the image. */
export async function parseArm64ExceptionTable(
  reader: FileRangeReader, source: FileRangeReader, declaredSize: number,
  rvaToOff: RvaToOffset, originRva?: number
): Promise<PeExceptionDirectory> {
  if (declaredSize < ARM64_RUNTIME_FUNCTION_ENTRY_SIZE) {
    return createEmptyExceptionDirectory([
      `Exception directory size is smaller than one ARM64 .pdata entry (${ARM64_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
    ], "arm64");
  }
  const issues: string[] = [];
  if (declaredSize % ARM64_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of ARM64 .pdata entry size (8 bytes).");
  }
  const state = createArm64ExceptionState();
  const readUnwindInfo = createArm64UnwindInfoReader(reader, rvaToOff, source, originRva, declaredSize);
  for await (const spanView of readRuntimeFunctionChunks(source,
    Math.floor(declaredSize / ARM64_RUNTIME_FUNCTION_ENTRY_SIZE), ARM64_RUNTIME_FUNCTION_ENTRY_SIZE,
    "Exception directory is truncated; some ARM64 .pdata entries are missing.", issues)) {
    const spanEntries = Math.floor(spanView.byteLength / ARM64_RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * ARM64_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const unwindWord = spanView.getUint32(entryOffset + Uint32Array.BYTES_PER_ELEMENT, true) >>> 0;
      await processArm64RuntimeFunction(
        reader, rvaToOff, beginRva, unwindWord, issues, state, readUnwindInfo
      );
    }
  }
  return summarizeArm64Table(state, issues);
}

const summarizeArm64Table = (state: Arm64ExceptionState, issues: string[]): PeExceptionDirectory => {
  if (state.functionCount === 0) {
    issues.push("Exception directory does not contain a complete ARM64 .pdata entry.");
    return createEmptyExceptionDirectory(issues, "arm64");
  }
  if (state.unexpectedXdataVersionCount > 0) {
    issues.push(`${state.unexpectedXdataVersionCount} ARM64 .xdata record(s) have an unexpected version.`);
  }
  return {
    functionCount: state.functionCount,
    beginRvas: state.beginRvas,
    rangeLengths: state.rangeLengths,
    handlerRvas: state.handlerRvas,
    ...(state.languageHandlers.length ? { languageHandlers: state.languageHandlers } : {}),
    uniqueUnwindInfoCount: state.uniqueUnwindInfos.size,
    handlerUnwindInfoCount: state.handlerUnwindInfoCount,
    chainedUnwindInfoCount: state.chainedUnwindInfoCount,
    invalidEntryCount: state.invalidEntryCount,
    issues,
    format: "arm64",
    arm64Packed: state.packed,
    arm64Unwind: state.unwind
  };
}
