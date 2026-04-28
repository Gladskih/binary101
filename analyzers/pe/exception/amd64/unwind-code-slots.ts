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

const isUnwindCodeArrayTruncated = (
  offset: number,
  codeBytes: number,
  fileSize: number
): boolean => offset < 0 || offset + Uint32Array.BYTES_PER_ELEMENT + codeBytes > fileSize;

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
  let sawNonEpilogCode = false;
  let hasLateEpilogCode = false;
  for (let codeIndex = 0; codeIndex < countOfCodes; codeIndex += 1) {
    const operationByte = codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT + 1);
    if ((operationByte & 0x0f) !== AMD64_UNWIND_V2_UOP_EPILOG) {
      sawNonEpilogCode = true;
      continue;
    }
    if (sawNonEpilogCode) {
      hasLateEpilogCode = true;
      continue;
    }
    const codeOffset = codeView.getUint8(codeIndex * Uint16Array.BYTES_PER_ELEMENT);
    if (codeOffset !== 0 || operationByte >> 4 !== 0) {
      epilogScopeCount += 1;
    }
  }
  return {
    epilogScopeCount,
    hasEpilogInfo: epilogScopeCount > 0,
    hasLateEpilogCode,
    isTruncated: false
  };
};
