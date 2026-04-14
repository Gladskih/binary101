"use strict";

import type { PeDynamicRelocationEntry } from "./index.js";

const DYNAMIC_RELOCATION_TABLE_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 2;
// Microsoft PE dynamic relocation table version 1: Symbol followed by BaseRelocSize.
const DYNAMIC_RELOCATION_V1_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT * 2;
const DYNAMIC_RELOCATION_V1_ENTRY_SIZE64 =
  BigUint64Array.BYTES_PER_ELEMENT + Uint32Array.BYTES_PER_ELEMENT;
// Version 2 entry header: HeaderSize + FixupInfoSize + Symbol + SymbolGroup + Flags.
const DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32 = Uint32Array.BYTES_PER_ELEMENT * 5;
const DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64 =
  Uint32Array.BYTES_PER_ELEMENT * 4 + BigUint64Array.BYTES_PER_ELEMENT;

const readU64Maybe = (view: DataView, offset: number): bigint => {
  if (view.byteLength < offset + BigUint64Array.BYTES_PER_ELEMENT) return 0n;
  return view.getBigUint64(offset, true);
};

export const parseDynamicRelocationEntriesV132 = (
  view: DataView,
  dataEnd: number,
  warnings: string[]
): PeDynamicRelocationEntry[] => {
  const entries: PeDynamicRelocationEntry[] = [];
  let cursor = DYNAMIC_RELOCATION_TABLE_HEADER_SIZE;
  while (cursor + DYNAMIC_RELOCATION_V1_ENTRY_SIZE32 <= dataEnd) {
    const symbol = BigInt(view.getUint32(cursor, true));
    const baseRelocSize = view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT, true);
    const relocStart = cursor + DYNAMIC_RELOCATION_V1_ENTRY_SIZE32;
    const availableBytes = Math.min(baseRelocSize, Math.max(0, dataEnd - relocStart));

    entries.push({ kind: "v1", symbol, baseRelocSize, availableBytes });
    cursor = relocStart + availableBytes;
    if (availableBytes < baseRelocSize) {
      warnings.push(
        `DynamicRelocations: V1 entry with symbol=${symbol} has BaseRelocSize=0x${baseRelocSize.toString(16)} but only 0x${availableBytes.toString(16)} bytes are available.`
      );
      break;
    }
  }
  if (cursor < dataEnd) {
    warnings.push(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V1 entry header/data.`);
  }
  return entries;
};

export const parseDynamicRelocationEntriesV164 = (
  view: DataView,
  dataEnd: number,
  warnings: string[]
): PeDynamicRelocationEntry[] => {
  const entries: PeDynamicRelocationEntry[] = [];
  let cursor = DYNAMIC_RELOCATION_TABLE_HEADER_SIZE;
  while (cursor + DYNAMIC_RELOCATION_V1_ENTRY_SIZE64 <= dataEnd) {
    const symbol = readU64Maybe(view, cursor);
    const baseRelocSize = view.getUint32(cursor + BigUint64Array.BYTES_PER_ELEMENT, true);
    const relocStart = cursor + DYNAMIC_RELOCATION_V1_ENTRY_SIZE64;
    const availableBytes = Math.min(baseRelocSize, Math.max(0, dataEnd - relocStart));

    entries.push({ kind: "v1", symbol, baseRelocSize, availableBytes });
    cursor = relocStart + availableBytes;
    if (availableBytes < baseRelocSize) {
      warnings.push(
        `DynamicRelocations: V1 entry with symbol=${symbol} has BaseRelocSize=0x${baseRelocSize.toString(16)} but only 0x${availableBytes.toString(16)} bytes are available.`
      );
      break;
    }
  }
  if (cursor < dataEnd) {
    warnings.push(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V1 entry header/data.`);
  }
  return entries;
};

export const parseDynamicRelocationEntriesV232 = (
  view: DataView,
  dataEnd: number,
  warnings: string[]
): PeDynamicRelocationEntry[] => {
  const entries: PeDynamicRelocationEntry[] = [];
  let cursor = DYNAMIC_RELOCATION_TABLE_HEADER_SIZE;
  while (cursor + DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32 <= dataEnd) {
    const headerSize = view.getUint32(cursor, true) >>> 0;
    const fixupInfoSize = view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT, true);
    const symbol = BigInt(view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT * 2, true));
    const symbolGroup = view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT * 3, true) >>> 0;
    const flags = view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT * 4, true) >>> 0;
    const entryBodySize = Math.max(0, dataEnd - cursor);
    if (headerSize < DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32) {
      warnings.push(
        `DynamicRelocations: V2 entry header size 0x${headerSize.toString(16)} is smaller than the fixed 0x${DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32.toString(16)}-byte structure.`
      );
    }
    if (entryBodySize <= DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32) {
      warnings.push(
        "DynamicRelocations: V2 entry body is no larger than the fixed header, so fixup payload is missing or truncated."
      );
    }
    const fixupStart = cursor + Math.max(DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE32, headerSize);
    const availableBytes = Math.min(fixupInfoSize, Math.max(0, dataEnd - fixupStart));

    entries.push({
      kind: "v2",
      headerSize,
      fixupInfoSize,
      symbol,
      symbolGroup,
      flags,
      availableBytes
    });
    cursor = fixupStart + availableBytes;
    if (availableBytes < fixupInfoSize) {
      warnings.push(
        `DynamicRelocations: V2 entry with symbol=${symbol} has FixupInfoSize=0x${fixupInfoSize.toString(16)} but only 0x${availableBytes.toString(16)} bytes are available.`
      );
      break;
    }
  }
  if (cursor < dataEnd) {
    warnings.push(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V2 entry header/data.`);
  }
  return entries;
};

export const parseDynamicRelocationEntriesV264 = (
  view: DataView,
  dataEnd: number,
  warnings: string[]
): PeDynamicRelocationEntry[] => {
  const entries: PeDynamicRelocationEntry[] = [];
  let cursor = DYNAMIC_RELOCATION_TABLE_HEADER_SIZE;
  while (cursor + DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64 <= dataEnd) {
    const headerSize = view.getUint32(cursor, true) >>> 0;
    const fixupInfoSize = view.getUint32(cursor + Uint32Array.BYTES_PER_ELEMENT, true);
    const symbol = readU64Maybe(view, cursor + Uint32Array.BYTES_PER_ELEMENT * 2);
    const symbolGroup = view.getUint32(cursor + 16, true) >>> 0;
    const flags = view.getUint32(cursor + 20, true) >>> 0;
    const entryBodySize = Math.max(0, dataEnd - cursor);
    if (headerSize < DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64) {
      warnings.push(
        `DynamicRelocations: V2 entry header size 0x${headerSize.toString(16)} is smaller than the fixed 0x${DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64.toString(16)}-byte structure.`
      );
    }
    if (entryBodySize <= DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64) {
      warnings.push(
        "DynamicRelocations: V2 entry body is no larger than the fixed header, so fixup payload is missing or truncated."
      );
    }
    const fixupStart = cursor + Math.max(DYNAMIC_RELOCATION_V2_ENTRY_HEADER_SIZE64, headerSize);
    const availableBytes = Math.min(fixupInfoSize, Math.max(0, dataEnd - fixupStart));

    entries.push({
      kind: "v2",
      headerSize,
      fixupInfoSize,
      symbol,
      symbolGroup,
      flags,
      availableBytes
    });
    cursor = fixupStart + availableBytes;
    if (availableBytes < fixupInfoSize) {
      warnings.push(
        `DynamicRelocations: V2 entry with symbol=${symbol} has FixupInfoSize=0x${fixupInfoSize.toString(16)} but only 0x${availableBytes.toString(16)} bytes are available.`
      );
      break;
    }
  }
  if (cursor < dataEnd) {
    warnings.push(`DynamicRelocations: trailing ${dataEnd - cursor} bytes after last parsed V2 entry header/data.`);
  }
  return entries;
};
