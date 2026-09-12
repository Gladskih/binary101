"use strict";

import { PE_RVA_EXCLUSIVE_LIMIT } from "./layout/rva-limits.js";
import type { RvaToOffset } from "./types.js";

export const isRvaRange = (rva: number, size: number): boolean =>
  Number.isSafeInteger(rva) && Number.isSafeInteger(size) && rva >= 0 && size > 0 &&
  rva < PE_RVA_EXCLUSIVE_LIMIT && size <= PE_RVA_EXCLUSIVE_LIMIT - rva;

const isPrefixRequest = (rva: number, size: number, fileSize: number): boolean =>
  isRvaRange(rva, 1) && Number.isSafeInteger(size) && size > 0 &&
  Number.isSafeInteger(fileSize) && fileSize > 0;

const isFileOffset = (offset: number | null, fileSize: number): offset is number =>
  offset != null && Number.isSafeInteger(offset) && offset >= 0 && offset < fileSize;

const pointMappedSize = (
  rvaToOff: RvaToOffset, rva: number, offset: number, limit: number
): number => {
  // Custom point mappers cannot prove continuity from endpoints alone.
  let length = 1;
  while (length < limit && rvaToOff(rva + length) === offset + length) length += 1;
  return length;
};

export const mappedRvaSpan = (
  rvaToOff: RvaToOffset, rva: number, size: number, fileSize: number
): { offset: number; size: number } | null => {
  if (!isPrefixRequest(rva, size, fileSize)) return null;
  const span = rvaToOff.span?.(rva);
  if (span && (!Number.isSafeInteger(span.size) || span.size <= 0)) return null;
  const offset = span ? span.offset : rvaToOff(rva);
  if (!isFileOffset(offset, fileSize)) return null;
  const limit = Math.min(size, fileSize - offset, PE_RVA_EXCLUSIVE_LIMIT - rva);
  if (span) return { offset, size: Math.min(limit, span.size) };
  return { offset, size: pointMappedSize(rvaToOff, rva, offset, limit) };
};

export const mappedRvaSize = (
  rvaToOff: RvaToOffset, rva: number, size: number, fileSize: number
): number => {
  let length = 0;
  while (length < size) {
    const span = mappedRvaSpan(rvaToOff, rva + length, size - length, fileSize);
    if (!span) break;
    length += span.size;
  }
  return length;
};

/** Only for consumers whose result explicitly requires one physical file range. */
export const contiguousRvaOffset = (
  rvaToOff: RvaToOffset, rva: number, size: number, fileSize: number
): number | null => {
  if (!isRvaRange(rva, size)) return null;
  const first = mappedRvaSpan(rvaToOff, rva, size, fileSize);
  if (!first) return null;
  let length = first.size;
  while (length < size) {
    const next = mappedRvaSpan(rvaToOff, rva + length, size - length, fileSize);
    if (!next || next.offset !== first.offset + length) return null;
    length += next.size;
  }
  return first.offset;
};
