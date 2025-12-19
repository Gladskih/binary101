"use strict";

import { readLoadConfigPointerRva } from "./load-config.js";
import type { RvaToOffset } from "./types.js";

// https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
// The CFG target tables (GFIDS and related) store an RVA plus optional metadata bytes.
// Entry size is 4 + n, where n is the "stride" subfield encoded in GuardFlags.
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28;

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
  const off = rvaToOff(tableRva);
  if (off == null || off < 0 || off >= file.size) return [];
  const maxEntries = Math.floor((file.size - off) / entrySize);
  const entriesToRead = Math.min(count, maxEntries);
  if (entriesToRead <= 0) return [];
  const dv = new DataView(await file.slice(off, off + entriesToRead * entrySize).arrayBuffer());
  const rvas: number[] = [];
  for (let index = 0; index < entriesToRead; index += 1) {
    const rva = readEntry(dv, index * entrySize) >>> 0;
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

  const out: number[] = [];
  for (const addressOrRva of rawValues) {
    const rva = readLoadConfigPointerRva(imageBase, addressOrRva);
    if (rva == null) continue;
    out.push(rva >>> 0);
  }
  return out;
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

