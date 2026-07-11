"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import {
  addReferenceMessage,
  readMappedReferenceView,
  type PeRvaMapping
} from "./reference-reader.js";
import type { PeHotPatchBase, PeHotPatchInfo } from "./reference-types.js";

// Field layouts and version annotations come from Windows SDK 10.0.26100.0 winnt.h.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
// Signal Labs confirmed by reversing NtManageHotPatch that Size covers the complete table and
// BaseImageList selects an array of table-relative offsets to IMAGE_HOT_PATCH_BASE records.
// https://github.com/Signal-Labs/Hotpatching_PoC/blob/main/hotpatch_poc/src/main.rs
const INFO_V1_SIZE = 20;
const INFO_V2_SIZE = 24;
const INFO_V3_SIZE = 28;
const INFO_V4_SIZE = 36;
const INFO_OFFSETS = {
  version: 0, size: 4, sequenceNumber: 8, baseImageList: 12, baseImageCount: 16,
  bufferOffset: 20, extraPatchSize: 24, minimumSequenceNumber: 28, flags: 32
} as const;
const BASE_V1_SIZE = 28;
const BASE_V2_SIZE = 32;
const BASE_OFFSETS = {
  sequenceNumber: 0, flags: 4, originalTimeDateStamp: 8, originalCheckSum: 12,
  codeIntegrityInfo: 16, codeIntegritySize: 20, patchTable: 24, bufferOffset: 28
} as const;
const HASHES_SIZE = 52;
type HotPatchTableRange = Readonly<{ rva: number; size: number }>;

const infoSizeForVersion = (version: number): number => {
  if (version >= 4) return INFO_V4_SIZE;
  if (version === 3) return INFO_V3_SIZE;
  if (version === 2) return INFO_V2_SIZE;
  return INFO_V1_SIZE;
};

const tableRvaAt = (tableRva: number, offset: number): number | null => {
  const result = tableRva + offset;
  return result < PE_RVA_EXCLUSIVE_LIMIT ? result : null;
};

const readTableView = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  table: HotPatchTableRange,
  offset: number,
  byteLength: number,
  label: string
): Promise<DataView | null> => {
  const itemRva = tableRvaAt(table.rva, offset);
  if (byteLength > table.size - offset || itemRva == null) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${label} leaves the declared HotPatch table.`);
    return null;
  }
  return readMappedReferenceView(reader, mapping, warnings, notes, label, itemRva, byteLength);
};

const bytesAt = (view: DataView, offset: number, size: number): number[] =>
  Array.from(new Uint8Array(view.buffer, view.byteOffset + offset, size));

const tableRangeFits = (table: HotPatchTableRange, offset: number, size: number): boolean => {
  const itemRva = tableRvaAt(table.rva, offset);
  return size <= table.size - offset && itemRva !== null && size <= PE_RVA_EXCLUSIVE_LIMIT - itemRva;
};

const readCodeIntegrityHashes = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  table: HotPatchTableRange,
  offset: number,
  size: number,
  index: number
): Promise<PeHotPatchBase["codeIntegrityHashes"]> => {
  if (offset === 0) {
    if (size !== 0) {
      addReferenceMessage(warnings,
        `LOAD_CONFIG: HotPatch base image ${index} has an incomplete IMAGE_HOT_PATCH_HASHES reference.`);
    }
    return undefined;
  }
  if (size < HASHES_SIZE) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: HotPatch base image ${index} has an incomplete IMAGE_HOT_PATCH_HASHES reference.`);
    return undefined;
  }
  if (!tableRangeFits(table, offset, size)) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: HotPatch base image ${index} hashes leave the declared HotPatch table.`);
  }
  const view = await readTableView(
    reader, mapping, warnings, notes, table, offset, HASHES_SIZE,
    `HotPatch base image ${index} hashes`
  );
  if (!view) return undefined;
  if (size > HASHES_SIZE) {
    addReferenceMessage(notes,
      `LOAD_CONFIG: HotPatch base image ${index} hashes have ${size - HASHES_SIZE} extension bytes.`);
  }
  return { sha256: bytesAt(view, 0, 32), sha1: bytesAt(view, 32, 20) };
};

const parseBase = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  table: HotPatchTableRange,
  offset: number,
  index: number,
  version: number
): Promise<PeHotPatchBase | null> => {
  const baseSize = version >= 2 ? BASE_V2_SIZE : BASE_V1_SIZE;
  const view = await readTableView(
    reader, mapping, warnings, notes, table, offset, baseSize,
    `HotPatch base image ${index}`
  );
  if (!view) return null;
  const codeIntegrityInfoOffset = view.getUint32(BASE_OFFSETS.codeIntegrityInfo, true);
  const codeIntegritySize = view.getUint32(BASE_OFFSETS.codeIntegritySize, true);
  const patchTableOffset = view.getUint32(BASE_OFFSETS.patchTable, true);
  if (patchTableOffset !== 0) {
    await readTableView(
      reader, mapping, warnings, notes, table, patchTableOffset, 4,
      `HotPatch base image ${index} PatchTable`
    );
    addReferenceMessage(notes,
      `LOAD_CONFIG: HotPatch base image ${index} PatchTable framing is unpublished; its offset is retained.`);
  }
  const codeIntegrityHashes = await readCodeIntegrityHashes(
    reader, mapping, warnings, notes, table,
    codeIntegrityInfoOffset, codeIntegritySize, index
  );
  return {
    offset,
    sequenceNumber: view.getUint32(BASE_OFFSETS.sequenceNumber, true),
    flags: view.getUint32(BASE_OFFSETS.flags, true),
    originalTimeDateStamp: view.getUint32(BASE_OFFSETS.originalTimeDateStamp, true),
    originalCheckSum: view.getUint32(BASE_OFFSETS.originalCheckSum, true),
    codeIntegrityInfoOffset,
    codeIntegritySize,
    patchTableOffset,
    ...(version >= 2 ? { bufferOffset: view.getUint32(BASE_OFFSETS.bufferOffset, true) } : {}),
    ...(codeIntegrityHashes ? { codeIntegrityHashes } : {})
  };
};

const parseBases = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  table: HotPatchTableRange,
  listOffset: number,
  count: number,
  version: number
): Promise<PeHotPatchBase[]> => {
  if (count === 0) return [];
  if (listOffset === 0) {
    addReferenceMessage(warnings,
      "LOAD_CONFIG: HotPatch BaseImageList has entries but its table-relative offset is zero.");
    return [];
  }
  const offsets = await readTableView(
    reader, mapping, warnings, notes, table, listOffset, count * 4,
    "HotPatch BaseImageList"
  );
  if (!offsets) return [];
  // Offset lists may alias a base record; cache its parse to avoid duplicate random I/O.
  const parsedByOffset = new Map<number, Promise<PeHotPatchBase | null>>();
  const parsed = await Promise.all(Array.from({ length: count }, (_, index) => {
    const offset = offsets.getUint32(index * 4, true);
    const existing = parsedByOffset.get(offset);
    if (existing) return existing;
    const base = parseBase(
      reader, mapping, warnings, notes, table, offset, index, version
    );
    parsedByOffset.set(offset, base);
    return base;
  }));
  return parsed.filter((base): base is PeHotPatchBase => base !== null);
};

const decodeInfo = (
  view: DataView,
  rva: number,
  version: number,
  size: number,
  baseImages: PeHotPatchBase[]
): PeHotPatchInfo => ({
  rva,
  version,
  size,
  sequenceNumber: view.getUint32(INFO_OFFSETS.sequenceNumber, true),
  baseImageListOffset: view.getUint32(INFO_OFFSETS.baseImageList, true),
  baseImageCount: view.getUint32(INFO_OFFSETS.baseImageCount, true),
  ...(version >= 2 ? { bufferOffset: view.getUint32(INFO_OFFSETS.bufferOffset, true) } : {}),
  ...(version >= 3 ? { extraPatchSize: view.getUint32(INFO_OFFSETS.extraPatchSize, true) } : {}),
  ...(version >= 4 ? {
    minSequenceNumber: view.getUint32(INFO_OFFSETS.minimumSequenceNumber, true),
    flags: view.getUint32(INFO_OFFSETS.flags, true)
  } : {}),
  baseImages
});

export const parseHotPatchInfo = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  rva: number
): Promise<PeHotPatchInfo | null> => {
  const initial = await readMappedReferenceView(
    reader, mapping, warnings, notes, "HotPatchTableOffset IMAGE_HOT_PATCH_INFO",
    rva, INFO_V1_SIZE
  );
  if (!initial) return null;
  const version = initial.getUint32(INFO_OFFSETS.version, true);
  const size = initial.getUint32(INFO_OFFSETS.size, true);
  const infoSize = infoSizeForVersion(version);
  if (size < infoSize) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: HotPatch version ${version} Size 0x${size.toString(16)} is too small.`);
    return null;
  }
  if (!mapping.rawChunks(rva, size)) {
    addReferenceMessage(warnings,
      "LOAD_CONFIG: HotPatch declared Size extends beyond mapped raw file data.");
  }
  const view = infoSize === INFO_V1_SIZE ? initial : await readTableView(
    reader, mapping, warnings, notes, { rva, size }, 0, infoSize,
    "HotPatchTableOffset IMAGE_HOT_PATCH_INFO"
  );
  if (!view) return null;
  if (version === 0) addReferenceMessage(warnings, "LOAD_CONFIG: HotPatch version 0 is invalid.");
  if (version > 4) {
    addReferenceMessage(notes, `LOAD_CONFIG: HotPatch version ${version} parsed using the known v4 fields.`);
  }
  const baseImageListOffset = view.getUint32(INFO_OFFSETS.baseImageList, true);
  const baseImageCount = view.getUint32(INFO_OFFSETS.baseImageCount, true);
  const baseImages = await parseBases(
    reader, mapping, warnings, notes, { rva, size },
    baseImageListOffset, baseImageCount, version
  );
  return decodeInfo(view, rva, version, size, baseImages);
};
