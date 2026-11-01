"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import { amd64UnwindOperationSlots, createAmd64UnwindOperationCollector,
  visitAmd64UnwindOperation } from "./unwind-operations.js";
import type { Amd64UnwindOperation, Amd64UnwindOperationVisitor } from "./unwind-v12-types.js";

// Conventional x64 UNWIND_INFO uses version 1; V3 has a separate payload decoder:
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
export const AMD64_UNWIND_INFO_VERSION_1 = 1;
// LLVM documents and emits Windows x64 unwind v2 for MSVC-compatible epilog unwind
// data (/d2epilogunwind): https://github.com/llvm/llvm-project/pull/129142
export const AMD64_UNWIND_INFO_VERSION_2 = 2;
// LLVM Win64EHDumper documents UOP_Epilog as the version 2 epilog descriptor opcode:
// https://github.com/llvm/llvm-project/commit/22011644
const AMD64_UNWIND_V2_UOP_EPILOG = 6;

export interface Amd64UnwindCodeStatus {
  issues: string[];
  epilogScopeCount: number;
  hasEpilogInfo: boolean;
  hasLateEpilogCode: boolean;
  isTruncated: boolean;
}

export interface Amd64UnwindCodeAnalysis extends Amd64UnwindCodeStatus {
  operations: Amd64UnwindOperation[];
}

const emptyStatus = (): Amd64UnwindCodeStatus => ({
  issues: [],
  epilogScopeCount: 0,
  hasEpilogInfo: false,
  hasLateEpilogCode: false,
  isTruncated: false
});

const emptyAnalysis = (): Amd64UnwindCodeAnalysis => ({ operations: [], ...emptyStatus() });

const truncatedAnalysis = (): Amd64UnwindCodeAnalysis => ({ ...emptyAnalysis(), isTruncated: true });

const isUnwindCodeArrayTruncated = (
  offset: number,
  codeBytes: number,
  fileSize: number
): boolean => !Number.isSafeInteger(offset) || offset < 0 ||
  offset + Uint32Array.BYTES_PER_ELEMENT + codeBytes > fileSize;

const readUnwindOperationByte = (codeView: DataView, codeIndex: number): number =>
  codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT + 1);

interface Amd64UnwindCodeScan {
  index: number;
  hasRegularCode: boolean;
  seenEpilogHeader: boolean;
  analysis: Amd64UnwindCodeStatus;
  visitor: Amd64UnwindOperationVisitor;
}

const readRegularOperation = (view: DataView, count: number, scan: Amd64UnwindCodeScan): boolean => {
  const byte = readUnwindOperationByte(view, scan.index);
  const slots = amd64UnwindOperationSlots(byte & 15, byte >>> 4);
  // CountOfCodes excludes padding and handler/chain tails; they cannot supply operands.
  if (scan.index + slots > count) {
    scan.analysis.isTruncated = true;
    return false;
  }
  if (!visitAmd64UnwindOperation(view, scan.index, scan.analysis.issues, scan.visitor)) return false;
  scan.index += slots;
  return true;
};

const recordEpilog = (view: DataView, scan: Amd64UnwindCodeScan): void => {
  const offset = view.getUint8(scan.index * 2);
  const info = readUnwindOperationByte(view, scan.index) >>> 4;
  // LLVM Win64EHDumper::printUnwindCode: the first UOP_Epilog stores length
  // and AtEnd (OpInfo bit0), not an explicit scope offset. Later zero offsets pad.
  // https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/tools/llvm-readobj/Win64EHDumper.cpp
  if (scan.hasRegularCode) scan.analysis.hasLateEpilogCode = true;
  else if (!scan.seenEpilogHeader) {
    scan.seenEpilogHeader = true;
    scan.analysis.hasEpilogInfo = true;
    if (info & 1) scan.analysis.epilogScopeCount++;
    if (info & ~1) scan.analysis.issues.push("AMD64 v2 epilog header has reserved flag bits.");
    if (offset === 0) scan.analysis.issues.push("AMD64 v2 epilog length is zero.");
  } else if (offset !== 0 || info !== 0) scan.analysis.epilogScopeCount++;
  scan.index++;
};

const analyzeUnwindOperations = (
  codeView: DataView,
  countOfCodes: number,
  version: number,
  visitor: Amd64UnwindOperationVisitor
): Amd64UnwindCodeStatus => {
  const scan: Amd64UnwindCodeScan = {
    index: 0, hasRegularCode: false, seenEpilogHeader: false, analysis: emptyStatus(), visitor
  };
  while (scan.index < countOfCodes) {
    const operationByte = readUnwindOperationByte(codeView, scan.index);
    const operationCode = operationByte & 0x0f;
    if (version === AMD64_UNWIND_INFO_VERSION_2 && operationCode === AMD64_UNWIND_V2_UOP_EPILOG) {
      recordEpilog(codeView, scan);
      continue;
    }
    scan.hasRegularCode = true;
    if (!readRegularOperation(codeView, countOfCodes, scan)) break;
  }
  return scan.analysis;
};

export const visitAmd64UnwindCodeSlots = (
  codeView: DataView, countOfCodes: number, version: number, visitor: Amd64UnwindOperationVisitor
): Amd64UnwindCodeStatus => {
  if (countOfCodes === 0) return emptyStatus();
  if (!Number.isSafeInteger(countOfCodes) || countOfCodes < 0 ||
      countOfCodes > Math.floor(codeView.byteLength / Uint16Array.BYTES_PER_ELEMENT)) {
    return { ...emptyStatus(), isTruncated: true };
  }
  if (version !== AMD64_UNWIND_INFO_VERSION_1 && version !== AMD64_UNWIND_INFO_VERSION_2) {
    return emptyStatus();
  }
  return analyzeUnwindOperations(codeView, countOfCodes, version, visitor);
};

export const decodeAmd64UnwindCodeSlots = (
  codeView: DataView, countOfCodes: number, version: number
): Amd64UnwindCodeAnalysis => {
  const operations: Amd64UnwindOperation[] = [];
  return { operations, ...visitAmd64UnwindCodeSlots(codeView, countOfCodes, version,
    createAmd64UnwindOperationCollector(operations)) };
};

export const analyzeAmd64UnwindCodeSlots = async (
  reader: FileRangeReader,
  offset: number,
  countOfCodes: number,
  version: number
): Promise<Amd64UnwindCodeAnalysis> => {
  const codeBytes = countOfCodes * Uint16Array.BYTES_PER_ELEMENT;
  if (codeBytes === 0) return emptyAnalysis();
  if (!Number.isSafeInteger(countOfCodes) || countOfCodes < 0) return truncatedAnalysis();
  if (isUnwindCodeArrayTruncated(offset, codeBytes, reader.size)) {
    return truncatedAnalysis();
  }
  const codeView = await reader.read(offset + Uint32Array.BYTES_PER_ELEMENT, codeBytes);
  return decodeAmd64UnwindCodeSlots(codeView, countOfCodes, version);
};
