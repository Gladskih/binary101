"use strict";

import type { RvaToOffset } from "../types.js";

const computeFunctionEndRva = (beginRva: number, functionLengthBytes: number): number | null => {
  if (!beginRva || functionLengthBytes <= 0) return null;
  const endRva = beginRva + functionLengthBytes;
  return Number.isSafeInteger(endRva) && endRva > beginRva && endRva <= 0xffffffff
    ? endRva >>> 0
    : null;
};

export const isValidArm64FunctionRange = (
  beginRva: number,
  functionLengthBytes: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  const endRva = computeFunctionEndRva(beginRva, functionLengthBytes);
  if (endRva == null) return false;
  const beginOff = rvaToOff(beginRva);
  const endOff = rvaToOff((endRva - 1) >>> 0);
  return beginOff != null && beginOff >= 0 && endOff != null && endOff >= 0 && endOff < fileSize;
};

export const isMappedArm64FunctionBegin = (
  beginRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  const beginOff = rvaToOff(beginRva);
  return beginRva !== 0 && beginOff != null && beginOff >= 0 && beginOff < fileSize;
};
