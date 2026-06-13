"use strict";

// Microsoft PE format: section VirtualAddress values and RVAs are 32-bit fields.
// Use 2^32 as the exclusive upper bound so high-RVA spans clamp instead of wrapping to 0.
export const PE_RVA_EXCLUSIVE_LIMIT = 0x1_0000_0000;

export const isRvaRangeInsideSizeOfImage = (
  rva: number,
  size: number,
  sizeOfImage: number
): boolean => {
  if (!Number.isInteger(rva) || !Number.isInteger(size) || !Number.isInteger(sizeOfImage)) return false;
  if (rva < 0 || size <= 0 || sizeOfImage <= 0) return false;
  const start = rva >>> 0;
  const end = start + (size >>> 0);
  return end > start && end <= (sizeOfImage >>> 0);
};
