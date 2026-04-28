"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
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
const UNW_FLAG_EHANDLER = 0x01;
const UNW_FLAG_UHANDLER = 0x02;
const UNW_FLAG_CHAININFO = 0x04;
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
}

interface Amd64UnwindScanState extends Amd64UnwindInfoTable {
  lateEpilogCodeCount: number;
  truncatedUnwindCodeArrayCount: number;
  unexpectedUnwindVersionCount: number;
  unreadableUnwindCount: number;
}

interface Amd64UnwindHeader {
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
  } else {
    state.unexpectedUnwindVersionCount += 1;
  }
};

const recordUnwindCodeAnalysis = async (
  reader: FileRangeReader,
  header: Amd64UnwindHeader,
  state: Amd64UnwindScanState
): Promise<void> => {
  const analysis = await analyzeAmd64UnwindCodeSlots(
    reader,
    header.offset,
    header.countOfCodes,
    header.version
  );
  if (analysis.isTruncated) state.truncatedUnwindCodeArrayCount += 1;
  if (analysis.hasLateEpilogCode) state.lateEpilogCodeCount += 1;
  if (!analysis.hasEpilogInfo) return;
  state.epilogUnwindInfoCount += 1;
  state.epilogScopeCount += analysis.epilogScopeCount;
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
  unwindInfoVersion2Count: state.unwindInfoVersion2Count
});

export const scanAmd64UnwindInfos = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  initialUnwindRvas: Set<number>,
  issues: string[]
): Promise<Amd64UnwindInfoTable> => {
  const state = createEmptyScanState();
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
    const header = unwindOffset == null ? null : await readUnwindHeader(reader, unwindOffset);
    if (!header) {
      state.unreadableUnwindCount += 1;
      continue;
    }
    recordVersion(header.version, state);
    await recordUnwindCodeAnalysis(reader, header, state);
    if ((header.flags & UNW_FLAG_CHAININFO) !== 0) {
      state.chainedUnwindInfoCount += 1;
      if ((header.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) !== 0) {
        issues.push("UNWIND_INFO sets CHAININFO together with EHANDLER/UHANDLER.");
      }
      const chainedRva = await readTrailingUint32(
        reader,
        header.offset + alignTo4(UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2) + 8,
        "UNWIND_INFO declares CHAININFO, but the trailing chained RUNTIME_FUNCTION is truncated.",
        issues
      );
      if (chainedRva) enqueueUnwindRva(chainedRva);
      continue;
    }
    if ((header.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) === 0) continue;
    state.handlerUnwindInfoCount += 1;
    const handlerRva = await readTrailingUint32(
      reader,
      header.offset + alignTo4(UNWIND_INFO_HEADER_SIZE + header.countOfCodes * 2),
      "UNWIND_INFO declares EHANDLER/UHANDLER, but the trailing handler RVA is truncated.",
      issues
    );
    if (handlerRva && !handlerRvasSet.has(handlerRva)) {
      handlerRvasSet.add(handlerRva);
      state.handlerRvas.push(handlerRva);
    }
  }
  state.uniqueUnwindInfoCount = visitedUnwindRvas.size;
  appendSummaryIssues(state, issues);
  return toUnwindInfoTable(state);
};
