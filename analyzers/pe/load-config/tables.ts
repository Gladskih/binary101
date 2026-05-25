"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  readLoadConfigPointerRva,
  type PeLoadConfigTable,
  type PeLoadConfigTableKind
} from "./index.js";
import type { RvaToOffset } from "../types.js";

// https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
// The CFG target tables (GFIDS and related) store an RVA plus optional metadata bytes.
// Entry size is 4 + n, where n is the "stride" subfield encoded in GuardFlags.
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28;
const IMAGE_GUARD_FLAG_FID_SUPPRESSED = 0x01;
const IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED = 0x02;
const GFIDS_FLAG_MASK = IMAGE_GUARD_FLAG_FID_SUPPRESSED | IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED;
export const getCfgTargetTableEntrySize = (guardFlags: number): number => {
  const flags = Number.isSafeInteger(guardFlags) ? (guardFlags >>> 0) : 0;
  const stride =
    ((flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>>
      IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) >>> 0;
  return 4 + stride;
};

const decodeGfidsFlags = (flags: number): string[] => [
  ...((flags & IMAGE_GUARD_FLAG_FID_SUPPRESSED) !== 0 ? ["FID_SUPPRESSED"] : []),
  ...((flags & IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED) !== 0 ? ["EXPORT_SUPPRESSED"] : [])
];

const readTableRvas = async (table: Promise<PeLoadConfigTable>): Promise<number[]> =>
  (await table).entries.map(entry => entry.rva);

const readLoadConfigRvaTable = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  tableVa: bigint,
  count: number,
  entrySize: number,
  kind: PeLoadConfigTableKind,
  name: string
): Promise<PeLoadConfigTable> => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const tableRva = readLoadConfigPointerRva(imageBase, tableVa);
  const result = (
    entries: PeLoadConfigTable["entries"],
    truncated: boolean
  ): PeLoadConfigTable => ({
    kind,
    name,
    tableVa,
    tableRva,
    declaredCount: Number.isSafeInteger(count) && count > 0 ? count : 0,
    entrySize: Number.isSafeInteger(entrySize) && entrySize > 0 ? entrySize : 0,
    entries,
    truncated,
    ...(notes.length ? { notes } : {}),
    ...(warnings.length ? { warnings } : {})
  });
  if (!Number.isSafeInteger(count) || count <= 0) return result([], false);
  if (!Number.isSafeInteger(entrySize) || entrySize <= 0) {
    warnings.push(`${name}: invalid entry size.`);
    return result([], true);
  }
  if (tableRva == null) {
    warnings.push(`${name}: table pointer is not a valid VA.`);
    return result([], true);
  }
  const tableOff = rvaToOff(tableRva);
  if (tableOff == null) {
    notes.push(`${name}: table RVA 0x${tableRva.toString(16)} is not backed by raw file data.`);
    return result([], true);
  }
  if (tableOff < 0 || tableOff >= reader.size) {
    warnings.push(`${name}: table RVA 0x${tableRva.toString(16)} maps outside file data.`);
    return result([], true);
  }
  const entries: PeLoadConfigTable["entries"] = [];
  for (let index = 0; index < count; index += 1) {
    const entryRva = (tableRva + index * entrySize) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null) {
      notes.push(`${name}: entry ${index} RVA 0x${entryRva.toString(16)} is not backed by raw file data.`);
      return result(entries, true);
    }
    if (entryOff < 0 || entryOff + entrySize > reader.size) {
      warnings.push(`${name}: entry ${index} maps outside complete file data.`);
      return result(entries, true);
    }
    const dv = await reader.read(entryOff, entrySize);
    if (dv.byteLength < entrySize) {
      warnings.push(`${name}: entry ${index} is truncated.`);
      return result(entries, true);
    }
    const rva = dv.getUint32(0, true) >>> 0;
    const metadataBytes = Array.from(
      { length: Math.max(0, entrySize - Uint32Array.BYTES_PER_ELEMENT) },
      (_, byteIndex) => dv.getUint8(Uint32Array.BYTES_PER_ELEMENT + byteIndex)
    );
    if (!rva) continue;
    const gfidsByte = kind === "guardFid" && metadataBytes.length ? metadataBytes[0] ?? 0 : 0;
    const unknownGfidsFlagBits = gfidsByte & ~GFIDS_FLAG_MASK;
    entries.push({
      index,
      rva,
      ...(metadataBytes.length ? { metadataBytes } : {}),
      ...(kind === "guardFid" && gfidsByte ? { gfidsFlags: decodeGfidsFlags(gfidsByte) } : {}),
      ...(kind === "guardFid" && unknownGfidsFlagBits ? { unknownGfidsFlagBits } : {})
    });
  }
  return result(entries, false);
};

export async function readGuardCFFunctionTable(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardCFFunctionTableVa: bigint,
  guardCFFunctionCount: number,
  guardFlags?: number
): Promise<PeLoadConfigTable> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readLoadConfigRvaTable(
    reader,
    rvaToOff,
    imageBase,
    guardCFFunctionTableVa,
    guardCFFunctionCount,
    entrySize,
    "guardFid",
    "GuardCFFunctionTable"
  );
}
export async function readGuardCFFunctionTableRvas(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardCFFunctionTableVa: bigint,
  guardCFFunctionCount: number,
  guardFlags?: number
): Promise<number[]> {
  return readTableRvas(readGuardCFFunctionTable(
    reader,
    rvaToOff,
    imageBase,
    guardCFFunctionTableVa,
    guardCFFunctionCount,
    guardFlags
  ));
}
export async function readSafeSehHandlerTable(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  seHandlerTableVa: bigint,
  seHandlerCount: number
): Promise<PeLoadConfigTable> {
  return readLoadConfigRvaTable(
    reader,
    rvaToOff,
    imageBase,
    seHandlerTableVa,
    seHandlerCount,
    4,
    "safeSeh",
    "SEHandlerTable"
  );
}
export async function readSafeSehHandlerTableRvas(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  seHandlerTableVa: bigint,
  seHandlerCount: number
): Promise<number[]> {
  return readTableRvas(readSafeSehHandlerTable(
    reader,
    rvaToOff,
    imageBase,
    seHandlerTableVa,
    seHandlerCount
  ));
}
export async function readGuardEhContinuationTable(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardEhContinuationTableVa: bigint,
  guardEhContinuationCount: number,
  guardFlags?: number
): Promise<PeLoadConfigTable> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readLoadConfigRvaTable(
    reader,
    rvaToOff,
    imageBase,
    guardEhContinuationTableVa,
    guardEhContinuationCount,
    entrySize,
    "guardEhContinuation",
    "GuardEHContinuationTable"
  );
}

export async function readGuardEhContinuationTableRvas(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardEhContinuationTableVa: bigint,
  guardEhContinuationCount: number,
  guardFlags?: number
): Promise<number[]> {
  return readTableRvas(readGuardEhContinuationTable(
    reader,
    rvaToOff,
    imageBase,
    guardEhContinuationTableVa,
    guardEhContinuationCount,
    guardFlags
  ));
}

export async function readGuardLongJumpTargetTable(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardLongJumpTargetTableVa: bigint,
  guardLongJumpTargetCount: number,
  guardFlags?: number
): Promise<PeLoadConfigTable> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readLoadConfigRvaTable(
    reader,
    rvaToOff,
    imageBase,
    guardLongJumpTargetTableVa,
    guardLongJumpTargetCount,
    entrySize,
    "guardLongJump",
    "GuardLongJumpTargetTable"
  );
}

export async function readGuardLongJumpTargetTableRvas(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardLongJumpTargetTableVa: bigint,
  guardLongJumpTargetCount: number,
  guardFlags?: number
): Promise<number[]> {
  return readTableRvas(readGuardLongJumpTargetTable(
    reader,
    rvaToOff,
    imageBase,
    guardLongJumpTargetTableVa,
    guardLongJumpTargetCount,
    guardFlags
  ));
}

export async function readGuardAddressTakenIatEntryTable(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardAddressTakenIatEntryTableVa: bigint,
  guardAddressTakenIatEntryCount: number,
  guardFlags?: number
): Promise<PeLoadConfigTable> {
  const entrySize = getCfgTargetTableEntrySize(guardFlags ?? 0);
  return readLoadConfigRvaTable(
    reader,
    rvaToOff,
    imageBase,
    guardAddressTakenIatEntryTableVa,
    guardAddressTakenIatEntryCount,
    entrySize,
    "guardIat",
    "GuardAddressTakenIatEntryTable"
  );
}

export async function readGuardAddressTakenIatEntryTableRvas(
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  guardAddressTakenIatEntryTableVa: bigint,
  guardAddressTakenIatEntryCount: number,
  guardFlags?: number
): Promise<number[]> {
  return readTableRvas(readGuardAddressTakenIatEntryTable(
    reader,
    rvaToOff,
    imageBase,
    guardAddressTakenIatEntryTableVa,
    guardAddressTakenIatEntryCount,
    guardFlags
  ));
}
