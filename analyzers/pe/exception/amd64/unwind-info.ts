"use strict";

import { createRvaRangeReader } from "../../rva-range-reader.js";
import type { FileRangeReader } from "../../../file-range-reader.js";
import { UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO, UNW_FLAG_LARGE }
  from "./unwind-flags.js";
import { readAmd64ChainedFunction } from "./handler-owners.js";
import type { PeLanguageHandler } from "../types.js";
import { isValidFunctionRange } from "../function-range.js";
import type { RvaToOffset } from "../../types.js";
import type { Amd64UnwindV3Statistics } from "./unwind-v3-types.js";
import { decodeAmd64UnwindV3 } from "./unwind-v3.js";
import { createV3Statistics, recordV3Statistics } from "./unwind-v3-statistics.js";
import { createV12Statistics, recordV12Statistics } from "./unwind-v12-statistics.js";
import type { Amd64UnwindV12Header, Amd64UnwindV12Statistics } from "./unwind-v12-types.js";
import {
  AMD64_UNWIND_INFO_VERSION_1,
  AMD64_UNWIND_INFO_VERSION_2,
  analyzeAmd64UnwindCodeSlots
} from "./unwind-code-slots.js";
import {
  createCachedRvaOffsetReader,
  createRvaFileOffsetComparer,
  insertPendingUnwindRva
} from "./unwind-rva-queue.js";

// Microsoft x64 exception handling:
// UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, and UNW_FLAG_CHAININFO are the public UNWIND_INFO flags.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
const UNWIND_INFO_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const alignTo4 = (value: number): number => (value + 3) & ~3;

export interface Amd64UnwindInfoTable {
  chainedUnwindInfoCount: number;
  epilogScopeCount: number;
  epilogUnwindInfoCount: number;
  handlerRvas: number[];
  handlerUnwindInfoCount: number;
  uniqueUnwindInfoCount: number;
  unwindInfoVersion1Count: number;
  unwindInfoVersion2Count: number;
  version3?: Amd64UnwindV3Statistics;
  version12?: Amd64UnwindV12Statistics;
  languageHandlers?: PeLanguageHandler[];
  chainedUnwindRvas?: Map<number, number>;
}

interface Amd64UnwindScanState extends Amd64UnwindInfoTable {
  lateEpilogCodeCount: number;
  truncatedUnwindCodeArrayCount: number;
  unexpectedUnwindVersionCount: number;
  unreadableUnwindCount: number;
}

interface Amd64UnwindHeader extends Amd64UnwindV12Header {
  countOfCodes: number;
  flags: number;
  offset: number;
  version: number;
}

const createEmptyScanState = (): Amd64UnwindScanState => ({
  chainedUnwindInfoCount: 0,
  epilogScopeCount: 0,
  epilogUnwindInfoCount: 0,
  handlerRvas: [],
  handlerUnwindInfoCount: 0,
  lateEpilogCodeCount: 0,
  truncatedUnwindCodeArrayCount: 0,
  unexpectedUnwindVersionCount: 0,
  unreadableUnwindCount: 0,
  uniqueUnwindInfoCount: 0,
  unwindInfoVersion1Count: 0,
  unwindInfoVersion2Count: 0
});

const readUint32 = async (
  reader: FileRangeReader,
  offset: number
): Promise<number | null> => {
  if (offset < 0 || offset + Uint32Array.BYTES_PER_ELEMENT > reader.size) return null;
  const view = await reader.read(offset, Uint32Array.BYTES_PER_ELEMENT);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT ? view.getUint32(0, true) >>> 0 : null;
};

const readTrailingUint32 = async (
  reader: FileRangeReader,
  offset: number,
  issue: string,
  issues: string[]
): Promise<number | null> => {
  const value = await readUint32(reader, offset);
  if (value == null) issues.push(issue);
  return value;
};

const readUnwindHeader = async (
  reader: FileRangeReader,
  offset: number
): Promise<Amd64UnwindHeader | null> => {
  if (offset < 0 || offset >= reader.size) return null;
  const headerView = await reader.read(offset, UNWIND_INFO_HEADER_SIZE);
  if (headerView.byteLength < UNWIND_INFO_HEADER_SIZE) return null;
  const headerByte0 = headerView.getUint8(0);
  return {
    countOfCodes: headerView.getUint8(2),
    prologSize: headerView.getUint8(1),
    frameRegister: headerView.getUint8(3) & 15,
    frameOffset: (headerView.getUint8(3) >>> 4) * 16,
    flags: headerByte0 >> 3,
    offset,
    version: headerByte0 & 0x07
  };
};

const recordVersion = (version: number, state: Amd64UnwindScanState): void => {
  if (version === AMD64_UNWIND_INFO_VERSION_1) {
    state.unwindInfoVersion1Count += 1;
  } else if (version === AMD64_UNWIND_INFO_VERSION_2) {
    state.unwindInfoVersion2Count += 1;
  } else if (version !== 3) {
    state.unexpectedUnwindVersionCount += 1;
  }
};

const hasRegularUnwindCodes = (version: number): boolean =>
  version === AMD64_UNWIND_INFO_VERSION_1 || version === AMD64_UNWIND_INFO_VERSION_2;

const recordV3CodeAnalysis = async (
  reader: FileRangeReader, header: Amd64UnwindHeader, state: Amd64UnwindScanState, issues: string[]
): Promise<boolean> => {
  state.version3 ??= createV3Statistics();
  const decodeIssues: string[] = [];
  const decoded = decodeAmd64UnwindV3(
    await reader.read(header.offset, UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2), decodeIssues);
  recordV3Statistics(state.version3, decoded);
  issues.push(...decodeIssues);
  return decoded != null && decodeIssues.length === 0;
};

const recordUnwindCodeAnalysis = async (
  reader: FileRangeReader,
  header: Amd64UnwindHeader,
  state: Amd64UnwindScanState,
  issues: string[]
): Promise<boolean> => {
  if (header.version === 3) {
    return recordV3CodeAnalysis(reader, header, state, issues);
  }
  if (!hasRegularUnwindCodes(header.version)) return false;
  const analysis = await analyzeAmd64UnwindCodeSlots(
    reader,
    header.offset,
    header.countOfCodes,
    header.version
  );
  state.version12 ??= createV12Statistics();
  recordV12Statistics(state.version12, header, analysis);
  issues.push(...analysis.issues);
  if (analysis.isTruncated) state.truncatedUnwindCodeArrayCount += 1;
  if (analysis.hasLateEpilogCode) state.lateEpilogCodeCount += 1;
  if (analysis.hasEpilogInfo) {
    state.epilogUnwindInfoCount += 1;
    state.epilogScopeCount += analysis.epilogScopeCount;
  }
  return !analysis.isTruncated && analysis.issues.length === 0 && !analysis.hasLateEpilogCode;
};

const appendSummaryIssues = (state: Amd64UnwindScanState, issues: string[]): void => {
  if (state.unreadableUnwindCount > 0) {
    issues.push(`${state.unreadableUnwindCount} UNWIND_INFO block(s) could not be read.`);
  }
  if (state.truncatedUnwindCodeArrayCount > 0) {
    issues.push(`${state.truncatedUnwindCodeArrayCount} UNWIND_INFO block(s) have a truncated unwind-code array.`);
  }
  if (state.unexpectedUnwindVersionCount > 0) {
    issues.push(`${state.unexpectedUnwindVersionCount} UNWIND_INFO block(s) have an unexpected version.`);
  }
  if (state.lateEpilogCodeCount > 0) {
    issues.push(`${state.lateEpilogCodeCount} UNWIND_INFO v2 block(s) place UOP_Epilog after regular unwind codes.`);
  }
};

const toUnwindInfoTable = (state: Amd64UnwindScanState): Amd64UnwindInfoTable => ({
  chainedUnwindInfoCount: state.chainedUnwindInfoCount,
  epilogScopeCount: state.epilogScopeCount,
  epilogUnwindInfoCount: state.epilogUnwindInfoCount,
  handlerRvas: state.handlerRvas,
  handlerUnwindInfoCount: state.handlerUnwindInfoCount,
  uniqueUnwindInfoCount: state.uniqueUnwindInfoCount,
  unwindInfoVersion1Count: state.unwindInfoVersion1Count,
  unwindInfoVersion2Count: state.unwindInfoVersion2Count,
  ...(state.version3 ? { version3: state.version3 } : {}),
  ...(state.version12 ? { version12: state.version12 } : {}),
  ...(state.languageHandlers ? { languageHandlers: state.languageHandlers } : {}),
  ...(state.chainedUnwindRvas ? { chainedUnwindRvas: state.chainedUnwindRvas } : {})
});

const recordLanguageHandler = (
  state: Amd64UnwindScanState, header: Amd64UnwindHeader, unwindInfoRva: number, handlerRva: number
): void => {
  // V3 adds LARGE (bit 3); its DWORD-aligned handler tail is unchanged.
  // https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-readobj/Win64EHDumper.cpp
  const allowedFlags = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER |
    (header.version === 3 ? UNW_FLAG_LARGE : 0);
  if ((header.flags & ~allowedFlags) !== 0) return;
  state.languageHandlers ??= [];
  state.languageHandlers.push({ unwindInfoRva, handlerRva,
    dataRva: unwindInfoRva + alignTo4(UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2) + 4 });
};

const recordChainLink = (
  state: Amd64UnwindScanState, header: Amd64UnwindHeader, unwindInfoRva: number, targetRva: number
): void => {
  const allowedFlags = UNW_FLAG_CHAININFO | (header.version === 3 ? UNW_FLAG_LARGE : 0);
  if ((header.flags & ~allowedFlags) !== 0) return;
  state.chainedUnwindRvas ??= new Map();
  state.chainedUnwindRvas.set(unwindInfoRva, targetRva);
};

const readUnwindChain = async (
  reader: FileRangeReader, header: Amd64UnwindHeader, state: Amd64UnwindScanState, issues: string[],
  enqueue: (rva: number) => void, validateRange: (begin: number, end: number) => boolean
): Promise<number | null> => {
  state.chainedUnwindInfoCount += 1;
  if ((header.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) !== 0) {
    issues.push("UNWIND_INFO sets CHAININFO together with EHANDLER/UHANDLER.");
  }
  const chain = await readAmd64ChainedFunction(reader,
    header.offset + alignTo4(UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2), issues, validateRange);
  if (chain?.rva) enqueue(chain.rva);
  return chain?.validRange ? chain.rva : null;
};

const recordHandlerTarget = (state: Amd64UnwindScanState, targets: Set<number>, rva: number | null): void => {
  if (!rva || targets.has(rva)) return;
  targets.add(rva);
  state.handlerRvas.push(rva);
};


const processUnwindInfo = async (
  unwindReader: FileRangeReader, header: Amd64UnwindHeader | null,
  state: Amd64UnwindScanState, issues: string[], enqueueUnwindRva: (rva: number) => void,
  handlerRvasSet: Set<number>, unwindInfoRva: number,
  validateRange: (begin: number, end: number) => boolean
): Promise<void> => {
  if (!header) {
    state.unreadableUnwindCount += 1;
    return;
  }
  recordVersion(header.version, state);
  const validCodes = await recordUnwindCodeAnalysis(unwindReader, header, state, issues);
  if ((header.flags & UNW_FLAG_CHAININFO) !== 0) {
    const target = await readUnwindChain(unwindReader, header, state, issues, enqueueUnwindRva, validateRange);
    if (target && validCodes) recordChainLink(state, header, unwindInfoRva, target);
    return;
  }
  if ((header.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) === 0) return;
  state.handlerUnwindInfoCount += 1;
  const handlerRva = await readTrailingUint32(
    unwindReader,
    header.offset + alignTo4(UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2),
    "UNWIND_INFO declares EHANDLER/UHANDLER, but the trailing handler RVA is truncated.",
    issues
  );
  if (handlerRva && validCodes) recordLanguageHandler(state, header, unwindInfoRva, handlerRva);
  recordHandlerTarget(state, handlerRvasSet, handlerRva);
};

export const scanAmd64UnwindInfos = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  initialUnwindRvas: Set<number>,
  issues: string[]
): Promise<Amd64UnwindInfoTable> => {
  const state = createEmptyScanState();
  const validateRange = (begin: number, end: number): boolean =>
    isValidFunctionRange(begin, end - begin, rvaToOff, reader.size);
  const handlerRvasSet = new Set<number>();
  const getUnwindOffset = createCachedRvaOffsetReader(rvaToOff);
  const compareUnwindRvas = createRvaFileOffsetComparer(getUnwindOffset);
  const unwindQueue = [...initialUnwindRvas.values()].sort(compareUnwindRvas);
  const visitedUnwindRvas = new Set<number>(initialUnwindRvas);
  let unwindQueueIndex = 0;
  const enqueueUnwindRva = (rva: number): void => {
    if (!rva || visitedUnwindRvas.has(rva)) return;
    visitedUnwindRvas.add(rva);
    insertPendingUnwindRva(unwindQueue, unwindQueueIndex, rva, compareUnwindRvas);
  };
  while (unwindQueueIndex < unwindQueue.length) {
    const unwindInfoRva = unwindQueue[unwindQueueIndex]!;
    unwindQueueIndex += 1;
    const unwindOffset = getUnwindOffset(unwindInfoRva);
    // CountOfCodes (v1/v2) or PayloadWords (v3) bounds the payload to 510 bytes.
    // DWORD alignment and a trailing 12-byte chain give a structural maximum of 528 bytes.
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
    const unwindReader = createRvaRangeReader(reader, rvaToOff, unwindInfoRva, 528);
    const header = unwindOffset == null ? null : await readUnwindHeader(unwindReader, 0);
    await processUnwindInfo(unwindReader, header, state, issues, enqueueUnwindRva,
      handlerRvasSet, unwindInfoRva, validateRange);
  }
  state.uniqueUnwindInfoCount = visitedUnwindRvas.size;
  appendSummaryIssues(state, issues);
  return toUnwindInfoTable(state);
};
