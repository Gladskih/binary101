"use strict";

import type { RvaToOffset } from "../types.js";
import { isRvaRange, mappedRvaSize } from "../rva-mapping.js";

export const isValidFunctionRange = (
  beginRva: number,
  functionLengthBytes: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  return beginRva !== 0 && isRvaRange(beginRva, functionLengthBytes) &&
    mappedRvaSize(rvaToOff, beginRva, functionLengthBytes, fileSize) === functionLengthBytes;
};

export const isMappedFunctionBegin = (
  beginRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): boolean => {
  return isValidFunctionRange(beginRva, 1, rvaToOff, fileSize);
};
