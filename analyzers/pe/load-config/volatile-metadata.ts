"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import {
  addReferenceMessage,
  readMappedReferenceTable,
  readMappedReferenceView,
  referencePointerRva,
  type PeRvaMapping
} from "./reference-reader.js";
import type { PeVolatileMetadata, PeVolatileMetadataRange } from "./reference-types.js";

// Recovered layout implemented independently by upstream LIEF and FEX.
// https://github.com/lief-project/LIEF/blob/main/src/PE/LoadConfigurations/VolatileMetadata.cpp
// https://github.com/FEX-Emu/FEX/commit/51281f6a3ac8acd91b91670d3e38132254f1bd30
const VOLATILE_METADATA_HEADER_SIZE = 24;
const VOLATILE_METADATA_OFFSETS = {
  size: 0, minimumVersion: 4, maximumVersion: 6, accessTableRva: 8,
  accessTableSize: 12, infoRangeTableRva: 16, infoRangeTableSize: 20
} as const;
const ACCESS_ENTRY_SIZE = 4;
const RANGE_ENTRY_SIZE = 8;

const readVolatileTable = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  name: string,
  tableRva: number,
  byteSize: number,
  entrySize: number
): Promise<DataView | null> => {
  if (byteSize % entrySize !== 0) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: volatile metadata ${name} size ${byteSize} is not divisible by ${entrySize}.`);
  }
  return readMappedReferenceTable(
    reader, mapping, warnings, notes, `volatile metadata ${name}`,
    tableRva, Math.floor(byteSize / entrySize), entrySize
  );
};

const readAccessRvas = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  tableRva: number,
  byteSize: number
): Promise<number[]> => {
  const view = await readVolatileTable(
    reader, mapping, warnings, notes, "access table", tableRva, byteSize, ACCESS_ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: view.byteLength / ACCESS_ENTRY_SIZE }, (_, index) =>
    view.getUint32(index * ACCESS_ENTRY_SIZE, true));
};

const readInfoRanges = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  tableRva: number,
  byteSize: number
): Promise<PeVolatileMetadataRange[]> => {
  const view = await readVolatileTable(
    reader, mapping, warnings, notes, "range table", tableRva, byteSize, RANGE_ENTRY_SIZE
  );
  if (!view) return [];
  return Array.from({ length: view.byteLength / RANGE_ENTRY_SIZE }, (_, index) => {
    const offset = index * RANGE_ENTRY_SIZE;
    return { rva: view.getUint32(offset, true), size: view.getUint32(offset + 4, true) };
  }).filter(range => {
    if (range.rva + range.size <= PE_RVA_EXCLUSIVE_LIMIT) return true;
    addReferenceMessage(warnings, "LOAD_CONFIG: volatile metadata range exceeds the 32-bit RVA address space.");
    return false;
  });
};

const validateDeclaredSize = (
  mapping: PeRvaMapping,
  warnings: string[],
  rva: number,
  size: number
): void => {
  if (mapping.rawSpan(rva) && !mapping.rawChunks(rva, size)) {
    addReferenceMessage(warnings, "LOAD_CONFIG: volatile metadata declared Size extends beyond raw file data.");
  }
};

export const parseVolatileMetadata = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  warnings: string[],
  notes: string[],
  pointerVa: bigint
): Promise<PeVolatileMetadata | null> => {
  const rva = referencePointerRva(imageBase, warnings, "VolatileMetadataPointer", pointerVa);
  if (rva == null) return null;
  const view = await readMappedReferenceView(
    reader, mapping, warnings, notes, "volatile metadata header", rva, VOLATILE_METADATA_HEADER_SIZE
  );
  if (!view) return null;
  const size = view.getUint32(VOLATILE_METADATA_OFFSETS.size, true);
  if (size < VOLATILE_METADATA_HEADER_SIZE) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: volatile metadata Size ${size} is smaller than ${VOLATILE_METADATA_HEADER_SIZE}.`);
    return null;
  }
  if (size > VOLATILE_METADATA_HEADER_SIZE) {
    addReferenceMessage(notes,
      `LOAD_CONFIG: volatile metadata has ${size - VOLATILE_METADATA_HEADER_SIZE} extension bytes with no known layout.`);
  }
  validateDeclaredSize(mapping, warnings, rva, size);
  const accessTableRva = view.getUint32(VOLATILE_METADATA_OFFSETS.accessTableRva, true);
  const accessTableSize = view.getUint32(VOLATILE_METADATA_OFFSETS.accessTableSize, true);
  const infoRangeTableRva = view.getUint32(VOLATILE_METADATA_OFFSETS.infoRangeTableRva, true);
  const infoRangeTableSize = view.getUint32(VOLATILE_METADATA_OFFSETS.infoRangeTableSize, true);
  const [accessRvas, infoRanges] = await Promise.all([
    readAccessRvas(reader, mapping, warnings, notes, accessTableRva, accessTableSize),
    readInfoRanges(reader, mapping, warnings, notes, infoRangeTableRva, infoRangeTableSize)
  ]);
  return {
    rva,
    size,
    minimumVersion: view.getUint16(VOLATILE_METADATA_OFFSETS.minimumVersion, true),
    maximumVersion: view.getUint16(VOLATILE_METADATA_OFFSETS.maximumVersion, true),
    accessTableRva,
    accessTableSize,
    infoRangeTableRva,
    infoRangeTableSize,
    accessRvas,
    infoRanges
  };
};
