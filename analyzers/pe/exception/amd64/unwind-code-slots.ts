"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";

// Microsoft Learn still documents x64 UNWIND_INFO version 1 as the public format:
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
export const AMD64_UNWIND_INFO_VERSION_1 = 1;
// LLVM documents and emits Windows x64 unwind v2 for MSVC-compatible epilog unwind
// data (/d2epilogunwind): https://github.com/llvm/llvm-project/pull/129142
export const AMD64_UNWIND_INFO_VERSION_2 = 2;
// LLVM Win64EHDumper documents UOP_Epilog as the version 2 epilog descriptor opcode:
// https://github.com/llvm/llvm-project/commit/22011644
const AMD64_UNWIND_V2_UOP_EPILOG = 6;

export interface Amd64UnwindCodeAnalysis {
  epilogScopeCount: number;
  hasEpilogInfo: boolean;
  hasLateEpilogCode: boolean;
  isTruncated: boolean;
}

const NO_UNWIND_CODE_ANALYSIS: Amd64UnwindCodeAnalysis = {
  epilogScopeCount: 0,
  hasEpilogInfo: false,
  hasLateEpilogCode: false,
  isTruncated: false
};

const TRUNCATED_UNWIND_CODE_ANALYSIS: Amd64UnwindCodeAnalysis = {
  epilogScopeCount: 0,
  hasEpilogInfo: false,
  hasLateEpilogCode: false,
  isTruncated: true
};

const regularUnwindSlotCount = (operationCode: number, operationInfo: number): number => {
  // Microsoft x64 exception handling documents which UWOP_* opcodes consume
  // trailing UNWIND_CODE slots as operands; those operand slots are raw data
  // and must not be decoded as independent operations.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
  // LLVM uses these same slot counts for v1/v2 (getNumUsedSlots):
  // https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-readobj/Win64EHDumper.cpp
  switch (operationCode) {
    case 1:
      return operationInfo === 0 ? 2 : 3;
    case 4:
    case 8:
      return 2;
    case 5:
    case 9:
      return 3;
    default:
      return 1;
  }
};

const isUnwindCodeArrayTruncated = (
  offset: number,
  codeBytes: number,
  fileSize: number
): boolean => offset < 0 || offset + Uint32Array.BYTES_PER_ELEMENT + codeBytes > fileSize;

const readUnwindOperationByte = (codeView: DataView, codeIndex: number): number =>
  codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT + 1);

const analyzeUnwindOperations = (
  codeView: DataView,
  countOfCodes: number,
  version: number
): Amd64UnwindCodeAnalysis => {
  let epilogScopeCount = 0;
  let codeIndex = 0;
  let hasRegularCode = false;
  let hasLateEpilogCode = false;
  let isTruncated = false;
  while (codeIndex < countOfCodes) {
    const operationByte = readUnwindOperationByte(codeView, codeIndex);
    const operationCode = operationByte & 0x0f;
    if (version === AMD64_UNWIND_INFO_VERSION_2 && operationCode === AMD64_UNWIND_V2_UOP_EPILOG) {
      if (hasRegularCode) hasLateEpilogCode = true;
      else if (codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT) !== 0 ||
        operationByte >> 4 !== 0) epilogScopeCount += 1;
      codeIndex += 1;
      continue;
    }
    hasRegularCode = true;
    const slotCount = regularUnwindSlotCount(operationCode, operationByte >> 4);
    // CountOfCodes excludes alignment padding and handler/chained data: those
    // bytes must never satisfy missing operands, even when present in the file.
    // Microsoft x64 exception handling, "Count of unwind codes" / "Unwind codes array".
    if (codeIndex + slotCount > countOfCodes) {
      isTruncated = true;
      break;
    }
    codeIndex += slotCount;
  }
  return {
    epilogScopeCount,
    hasEpilogInfo: epilogScopeCount > 0,
    hasLateEpilogCode,
    isTruncated
  };
};

export const analyzeAmd64UnwindCodeSlots = async (
  reader: FileRangeReader,
  offset: number,
  countOfCodes: number,
  version: number
): Promise<Amd64UnwindCodeAnalysis> => {
  const codeBytes = countOfCodes * Uint16Array.BYTES_PER_ELEMENT;
  if (codeBytes === 0) return NO_UNWIND_CODE_ANALYSIS;
  if (isUnwindCodeArrayTruncated(offset, codeBytes, reader.size)) {
    return TRUNCATED_UNWIND_CODE_ANALYSIS;
  }
  const codeView = await reader.read(offset + Uint32Array.BYTES_PER_ELEMENT, codeBytes);
  if (codeView.byteLength < codeBytes) return TRUNCATED_UNWIND_CODE_ANALYSIS;
  if (version !== AMD64_UNWIND_INFO_VERSION_1 && version !== AMD64_UNWIND_INFO_VERSION_2) {
    return NO_UNWIND_CODE_ANALYSIS;
  }
  return analyzeUnwindOperations(codeView, countOfCodes, version);
};
