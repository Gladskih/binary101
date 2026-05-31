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
  if (version !== AMD64_UNWIND_INFO_VERSION_2) return NO_UNWIND_CODE_ANALYSIS;
  let epilogScopeCount = 0;
  let codeIndex = 0;
  while (codeIndex < countOfCodes) {
    const operationByte = readUnwindOperationByte(codeView, codeIndex);
    if ((operationByte & 0x0f) !== AMD64_UNWIND_V2_UOP_EPILOG) break;
    const codeOffset = codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT);
    if (codeOffset !== 0 || operationByte >> 4 !== 0) {
      epilogScopeCount += 1;
    }
    codeIndex += 1;
  }
  let hasLateEpilogCode = false;
  while (codeIndex < countOfCodes) {
    const operationByte = readUnwindOperationByte(codeView, codeIndex);
    const operationCode = operationByte & 0x0f;
    if (operationCode === AMD64_UNWIND_V2_UOP_EPILOG) {
      hasLateEpilogCode = true;
      break;
    }
    codeIndex += regularUnwindSlotCount(operationCode, operationByte >> 4);
  }
  return {
    epilogScopeCount,
    hasEpilogInfo: epilogScopeCount > 0,
    hasLateEpilogCode,
    isTruncated: false
  };
};
