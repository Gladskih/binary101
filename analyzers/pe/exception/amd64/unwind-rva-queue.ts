"use strict";

import type { RvaToOffset } from "../../types.js";

export const createCachedRvaOffsetReader = (
  rvaToOff: RvaToOffset
): ((rva: number) => number | null) => {
  const offsets = new Map<number, number | null>();
  return (rva: number): number | null => {
    if (offsets.has(rva)) {
      return offsets.get(rva) ?? null;
    }
    const offset = rvaToOff(rva);
    const mappedOffset = offset == null ? null : offset;
    offsets.set(rva, mappedOffset);
    return mappedOffset;
  };
};

export const createRvaFileOffsetComparer = (
  getOffset: (rva: number) => number | null
): ((left: number, right: number) => number) =>
  (left: number, right: number): number => {
    const leftOffset = getOffset(left);
    const rightOffset = getOffset(right);
    if (leftOffset == null) {
      return rightOffset == null ? left - right : 1;
    }
    if (rightOffset == null) {
      return -1;
    }
    return leftOffset - rightOffset || left - right;
  };

export const insertPendingUnwindRva = (
  pendingUnwindRvas: number[],
  firstPendingIndex: number,
  unwindInfoRva: number,
  compareRvas: (left: number, right: number) => number
): void => {
  let low = firstPendingIndex;
  let high = pendingUnwindRvas.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (compareRvas(pendingUnwindRvas[mid]!, unwindInfoRva) <= 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  pendingUnwindRvas.splice(low, 0, unwindInfoRva);
};
