"use strict";

import { readLoadConfigPointerRva } from "./load-config.js";
import type { RvaToOffset } from "./types.js";

// https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
// The CFG target tables (GFIDS and related) store an RVA plus optional metadata bytes.
// Entry size is 4 + n, where n is the "stride" subfield encoded in GuardFlags.
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28;
// Compatibility heuristic, not spec: some legacy samples encode absolute VAs instead of the
// SafeSEH RVAs required by the PE format. Restrict VA reinterpretation to values clustered near
// ImageBase so we do not corrupt legitimate large RVAs that merely compare above ImageBase.
const SAFESEH_COMPAT_VA_WINDOW = 0x10_0000;

export const getCfgTargetTableEntrySize = (guardFlags: number): number => {
  const flags = Number.isSafeInteger(guardFlags) ? (guardFlags >>> 0) : 0;
  const stride = ((flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) >>> 0;
  return 4 + stride;
};

const readRvaTable = async (
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  tableVa: number,
  count: number,
  entrySize: number,
  readEntry: (view: DataView, entryOffset: number) => number
): Promise<number[]> => {
  if (!Number.isSafeInteger(count) || count <= 0) return [];
  if (!Number.isSafeInteger(entrySize) || entrySize <= 0) return [];
  const tableRva = readLoadConfigPointerRva(imageBase, tableVa);
  if (tableRva == null) return [];
  const rvas: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const entryRva = (tableRva + index * entrySize) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + entrySize > file.size) break;
    const dv = new DataView(await file.slice(entryOff, entryOff + entrySize).arrayBuffer());
    if (dv.byteLength < entrySize) break;
    const rva = readEntry(dv, 0) >>> 0;
    if (rva) rvas.push(rva);
  }
  return rvas;
};

export async function readGuardCFFunctionTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardCFFunctionTableVa: number,
  guardCFFunctionCount: number,
  guardFlags?: number
): Promise<number[]> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardCFFunctionTableVa,
    guardCFFunctionCount,
    entrySize,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}

export async function readSafeSehHandlerTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  seHandlerTableVa: number,
  seHandlerCount: number
): Promise<number[]> {
  const rawValues = await readRvaTable(
    file,
    rvaToOff,
    imageBase,
    seHandlerTableVa,
    seHandlerCount,
    4,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );

  const allEntriesLookLikeAbsoluteVasNearImageBase =
    rawValues.length > 1 &&
    imageBase > 0 &&
    rawValues.every(value => value >= imageBase && value - imageBase < SAFESEH_COMPAT_VA_WINDOW);
  if (!allEntriesLookLikeAbsoluteVasNearImageBase) return rawValues.map(value => value >>> 0);
  return rawValues.map(value => readLoadConfigPointerRva(imageBase, value) ?? (value >>> 0));
}

export async function readGuardEhContinuationTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardEhContinuationTableVa: number,
  guardEhContinuationCount: number,
  guardFlags?: number
): Promise<number[]> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardEhContinuationTableVa,
    guardEhContinuationCount,
    entrySize,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}

export async function readGuardLongJumpTargetTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardLongJumpTargetTableVa: number,
  guardLongJumpTargetCount: number,
  guardFlags?: number
): Promise<number[]> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardLongJumpTargetTableVa,
    guardLongJumpTargetCount,
    entrySize,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}

export async function readGuardAddressTakenIatEntryTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardAddressTakenIatEntryTableVa: number,
  guardAddressTakenIatEntryCount: number,
  guardFlags?: number
): Promise<number[]> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardAddressTakenIatEntryTableVa,
    guardAddressTakenIatEntryCount,
    entrySize,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}
