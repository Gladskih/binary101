"use strict";

// PE32/PE32+ RVAs are unsigned 32-bit values; 2^32 is the exclusive upper bound.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
export const PE_RVA_EXCLUSIVE_LIMIT = 0x1_0000_0000;

export const isRvaField = (value: number): boolean =>
  Number.isInteger(value) && value >= 0 && value < PE_RVA_EXCLUSIVE_LIMIT;

export const isRvaRangeInsideSizeOfImage = (
  rva: number,
  size: number,
  sizeOfImage: number
): boolean => {
  return isRvaField(rva) && isRvaField(size) && isRvaField(sizeOfImage) &&
    size > 0 && rva + size <= sizeOfImage;
};
