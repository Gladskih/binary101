"use strict";
import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";
export interface PeLoadConfig {
  Size: number;
  TimeDateStamp: number;
  Major: number;
  Minor: number;
  SecurityCookie: number;
  SEHandlerTable: number;
  SEHandlerCount: number;
  GuardCFCheckFunctionPointer: number;
  GuardCFDispatchFunctionPointer: number;
  GuardCFFunctionTable: number;
  GuardCFFunctionCount: number;
  GuardAddressTakenIatEntryTable: number;
  GuardAddressTakenIatEntryCount: number;
  GuardLongJumpTargetTable: number;
  GuardLongJumpTargetCount: number;
  GuardEHContinuationTable: number;
  GuardEHContinuationCount: number;
  GuardXFGCheckFunctionPointer: number;
  GuardXFGDispatchFunctionPointer: number;
  GuardXFGTableDispatchFunctionPointer: number;
  GuardMemcpyFunctionPointer: number;
  GuardFlags: number;
  warnings?: string[];
}
const MAX_RVA_BIGINT = 0xffff_ffffn;
const toRvaFromVa = (virtualAddress: number, imageBase: number): number | null => {
  if (!Number.isSafeInteger(virtualAddress) || virtualAddress <= 0) return null;
  if (!Number.isSafeInteger(imageBase) || imageBase < 0) return null;
  const va = BigInt(virtualAddress);
  const base = BigInt(imageBase);
  if (va < base) return null;
  const delta = va - base;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
};
const toRvaFromPointer = (value: number, imageBase: number): number | null => {
  const converted = toRvaFromVa(value, imageBase);
  if (converted != null) return converted;
  if (!Number.isSafeInteger(imageBase) || imageBase < 0) return null;
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  if (value > 0xffff_ffff) return null;
  return value >>> 0;
};
const toSafeU64 = (value: bigint): number => {
  const maxSafeBigInt = BigInt(Number.MAX_SAFE_INTEGER);
  return value <= maxSafeBigInt ? Number(value) : 0;
};
export async function parseLoadConfigDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  isPlus: boolean
): Promise<PeLoadConfig | null> {
  const lcDir = dataDirs.find(d => d.name === "LOAD_CONFIG");
  if (!lcDir?.rva || lcDir.size < 0x40) return null;
  const base = rvaToOff(lcDir.rva);
  if (base == null) return null;
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (base >= fileSize) return null;
  const availableSize = Math.min(lcDir.size, Math.max(0, fileSize - base));
  addCoverageRegion("LOAD_CONFIG", base, availableSize);
  const view = new DataView(await file.slice(base, base + Math.min(availableSize, 0x200)).arrayBuffer());
  const Size = view.getUint32(0, true);
  const TimeDateStamp = view.getUint32(4, true);
  const Major = view.getUint16(8, true);
  const Minor = view.getUint16(10, true);
  const declaredSize = Number.isFinite(Size) && Size > 0 && Size <= 0x10000 ? Size : 0;
  const withinDeclared = (endExclusive: number): boolean => !declaredSize || declaredSize >= endExclusive;
  const has = (offset: number, byteLength: number): boolean =>
    view.byteLength >= offset + byteLength && withinDeclared(offset + byteLength);
  const readU32 = (offset: number): number => (has(offset, 4) ? view.getUint32(offset, true) : 0);
  const readU64 = (offset: number): number => (has(offset, 8) ? toSafeU64(view.getBigUint64(offset, true)) : 0);
  const readCount32 = (offset: number): number => readU32(offset);
  const readCount64 = (offset: number): number => readU64(offset);
  let SecurityCookie = 0;
  let SEHandlerTable = 0;
  let SEHandlerCount = 0;
  let GuardCFCheckFunctionPointer = 0;
  let GuardCFDispatchFunctionPointer = 0;
  let GuardCFFunctionTable = 0;
  let GuardCFFunctionCount = 0;
  let GuardAddressTakenIatEntryTable = 0;
  let GuardAddressTakenIatEntryCount = 0;
  let GuardLongJumpTargetTable = 0;
  let GuardLongJumpTargetCount = 0;
  let GuardEHContinuationTable = 0;
  let GuardEHContinuationCount = 0;
  let GuardXFGCheckFunctionPointer = 0;
  let GuardXFGDispatchFunctionPointer = 0;
  let GuardXFGTableDispatchFunctionPointer = 0;
  let GuardMemcpyFunctionPointer = 0;
  let GuardFlags = 0;
  if (isPlus) {
    SecurityCookie = readU64(0x58);
    SEHandlerTable = readU64(0x60);
    SEHandlerCount = readCount64(0x68);
    GuardCFCheckFunctionPointer = readU64(0x70);
    GuardCFDispatchFunctionPointer = readU64(0x78);
    GuardCFFunctionTable = readU64(0x80);
    GuardCFFunctionCount = readCount64(0x88);
    GuardFlags = readU32(0x90);
    GuardAddressTakenIatEntryTable = readU64(0xa0);
    GuardAddressTakenIatEntryCount = readCount64(0xa8);
    GuardLongJumpTargetTable = readU64(0xb0);
    GuardLongJumpTargetCount = readCount64(0xb8);
    GuardEHContinuationTable = readU64(0x108);
    GuardEHContinuationCount = readCount64(0x110);
    GuardXFGCheckFunctionPointer = readU64(0x118);
    GuardXFGDispatchFunctionPointer = readU64(0x120);
    GuardXFGTableDispatchFunctionPointer = readU64(0x128);
    GuardMemcpyFunctionPointer = readU64(0x138);
  } else {
    SecurityCookie = readU32(0x3c);
    SEHandlerTable = readU32(0x40);
    SEHandlerCount = readCount32(0x44);
    GuardCFCheckFunctionPointer = readU32(0x48);
    GuardCFDispatchFunctionPointer = readU32(0x4c);
    GuardCFFunctionTable = readU32(0x50);
    GuardCFFunctionCount = readCount32(0x54);
    GuardFlags = readU32(0x58);
    GuardAddressTakenIatEntryTable = readU32(0x68);
    GuardAddressTakenIatEntryCount = readCount32(0x6c);
    GuardLongJumpTargetTable = readU32(0x70);
    GuardLongJumpTargetCount = readCount32(0x74);
    GuardEHContinuationTable = readU32(0xa4);
    GuardEHContinuationCount = readCount32(0xa8);
    GuardXFGCheckFunctionPointer = readU32(0xac);
    GuardXFGDispatchFunctionPointer = readU32(0xb0);
    GuardXFGTableDispatchFunctionPointer = readU32(0xb4);
    GuardMemcpyFunctionPointer = readU32(0xbc);
  }
  return {
    Size,
    TimeDateStamp,
    Major,
    Minor,
    SecurityCookie: SecurityCookie || 0,
    SEHandlerTable: SEHandlerTable || 0,
    SEHandlerCount,
    GuardCFCheckFunctionPointer: GuardCFCheckFunctionPointer || 0,
    GuardCFDispatchFunctionPointer: GuardCFDispatchFunctionPointer || 0,
    GuardCFFunctionTable: GuardCFFunctionTable || 0,
    GuardCFFunctionCount,
    GuardAddressTakenIatEntryTable: GuardAddressTakenIatEntryTable || 0,
    GuardAddressTakenIatEntryCount,
    GuardLongJumpTargetTable: GuardLongJumpTargetTable || 0,
    GuardLongJumpTargetCount,
    GuardEHContinuationTable: GuardEHContinuationTable || 0,
    GuardEHContinuationCount,
    GuardXFGCheckFunctionPointer: GuardXFGCheckFunctionPointer || 0,
    GuardXFGDispatchFunctionPointer: GuardXFGDispatchFunctionPointer || 0,
    GuardXFGTableDispatchFunctionPointer: GuardXFGTableDispatchFunctionPointer || 0,
    GuardMemcpyFunctionPointer: GuardMemcpyFunctionPointer || 0,
    GuardFlags
  };
}
export function readLoadConfigPointerRva(imageBase: number, pointerVa: number): number | null {
  return toRvaFromPointer(pointerVa, imageBase);
}
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
  const tableRva = toRvaFromPointer(tableVa, imageBase);
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
  guardCFFunctionCount: number
): Promise<number[]> {
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardCFFunctionTableVa,
    guardCFFunctionCount,
    8,
    (dv, entryOff) => dv.getUint32(entryOff + 0, true)
  );
}

export async function readSafeSehHandlerTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  seHandlerTableVa: number,
  seHandlerCount: number
): Promise<number[]> {
  const rvas = await readRvaTable(
    file,
    rvaToOff,
    imageBase,
    seHandlerTableVa,
    seHandlerCount,
    4,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );

  const out: number[] = [];
  for (const addressOrRva of rvas) {
    const rva = addressOrRva < imageBase ? addressOrRva : toRvaFromVa(addressOrRva, imageBase);
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
  guardEhContinuationCount: number
): Promise<number[]> {
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardEhContinuationTableVa,
    guardEhContinuationCount,
    4,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}

export async function readGuardLongJumpTargetTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardLongJumpTargetTableVa: number,
  guardLongJumpTargetCount: number
): Promise<number[]> {
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardLongJumpTargetTableVa,
    guardLongJumpTargetCount,
    4,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}

export async function readGuardAddressTakenIatEntryTableRvas(
  file: File,
  rvaToOff: RvaToOffset,
  imageBase: number,
  guardAddressTakenIatEntryTableVa: number,
  guardAddressTakenIatEntryCount: number
): Promise<number[]> {
  return readRvaTable(
    file,
    rvaToOff,
    imageBase,
    guardAddressTakenIatEntryTableVa,
    guardAddressTakenIatEntryCount,
    4,
    (dv, entryOff) => dv.getUint32(entryOff, true)
  );
}
