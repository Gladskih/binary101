"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import {
  readLoadConfigPointerRva,
  type PeLoadConfigTable,
  type PeLoadConfigTableKind
} from "./index.js";
import { decodeLoadConfigTableEntry } from "./table-record.js";
import type { RvaToOffset } from "../types.js";

// PE metadata defines CFG entries as an RVA plus the stride encoded in GuardFlags.
// https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28;
export const getCfgTargetTableEntrySize = (guardFlags: number): number => {
  const flags = Number.isSafeInteger(guardFlags) ? (guardFlags >>> 0) : 0;
  const stride =
    ((flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>>
      IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) >>> 0;
  return 4 + stride;
};

const readTableRvas = async (table: Promise<PeLoadConfigTable>): Promise<number[]> =>
  (await table).entries.map(entry => entry.rva);

const createTableResult = (
  kind: PeLoadConfigTableKind,
  name: string,
  tableVa: bigint,
  tableRva: number | null,
  count: number,
  entrySize: number,
  notes: string[],
  warnings: string[]
) => (
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
  const warnings: string[] = [], notes: string[] = [];
  const tableRva = readLoadConfigPointerRva(imageBase, tableVa);
  const result = createTableResult(
    kind, name, tableVa, tableRva, count, entrySize, notes, warnings
  );
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
  if (count > Math.floor((PE_RVA_EXCLUSIVE_LIMIT - tableRva) / entrySize)) {
    warnings.push(`${name}: declared entries exceed the 32-bit RVA address space.`);
    return result([], true);
  }
  const entries: PeLoadConfigTable["entries"] = [];
  for (let index = 0; index < count; index += 1) {
    const entryRva = tableRva + index * entrySize;
    const dv = await readMappedRvaPrefix(reader, entryRva, entrySize, rvaToOff);
    if (dv.byteLength < entrySize) {
      warnings.push(`${name}: entry ${index} is truncated or not fully backed by raw file data.`);
      return result(entries, true);
    }
    const entry = decodeLoadConfigTableEntry(dv, index, kind);
    if (entry) entries.push(entry);
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
