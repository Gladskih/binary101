"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeCodeViewEntry } from "./codeview.js";
import { decodeDebugEntryPayload, type PeDebugPayloads } from "./entry-decoders.js";
import { DEBUG_TYPE_NAMES } from "./types.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

export type { PeCodeViewEntry } from "./codeview.js";
export type {
  PeCoffAuxiliaryRecord,
  PeCoffDebugHeader,
  PeCoffDebugInfo,
  PeCoffLineNumber,
  PeCoffLineNumberBlock,
  PeCoffSymbol
} from "./coff.js";
export type { PeEmbeddedPortablePdbInfo } from "./embedded-portable-pdb.js";
export type { PeExDllCharacteristicsInfo } from "./ex-dll-characteristics.js";
export type { PeFpoInfo, PeFpoRecord } from "./fpo.js";
export type { PeMiscDebugInfo } from "./misc.js";
export type { PePdbChecksumInfo } from "./pdb-checksum.js";
export type { PePogoEntry, PePogoInfo } from "./pogo.js";
export type { PeR2rPerfMapInfo } from "./r2r-perfmap.js";
export type { PeRawDebugPayload } from "./raw-payload.js";
export type { PeReproInfo } from "./repro.js";
export type { PeVcFeatureInfo } from "./vc-feature.js";

// Microsoft PE format, "Debug Directory (Image Only)":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
// IMAGE_DEBUG_DIRECTORY entry layout (28 bytes, file form):
// - Characteristics (DWORD, reserved, must be 0) at +0x00
// - Type (DWORD) at +0x0c
// - SizeOfData (DWORD) at +0x10
// - AddressOfRawData (DWORD, RVA) at +0x14
// - PointerToRawData (DWORD, file offset) at +0x18
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
const IMAGE_DEBUG_DIRECTORY_OFF_CHARACTERISTICS = 0x00;
const IMAGE_DEBUG_DIRECTORY_OFF_TYPE = 0x0c;
const IMAGE_DEBUG_DIRECTORY_OFF_SIZE_OF_DATA = 0x10;
const IMAGE_DEBUG_DIRECTORY_OFF_ADDRESS_OF_RAW_DATA = 0x14;
const IMAGE_DEBUG_DIRECTORY_OFF_POINTER_TO_RAW_DATA = 0x18;

type FileRange = { start: number; end: number };

export interface PeDebugDirectoryEntry extends PeDebugPayloads {
  characteristics: number;
  type: number;
  typeName: string;
  sizeOfData: number;
  addressOfRawData: number;
  pointerToRawData: number;
}

const appendFileRange = (ranges: FileRange[], start: number, end: number, fileSize: number): void => {
  const safeStart = Math.max(0, Math.min(start, fileSize));
  const safeEnd = Math.max(0, Math.min(end, fileSize));
  if (safeEnd <= safeStart) return;
  const previous = ranges[ranges.length - 1];
  if (previous && previous.end >= safeStart) {
    previous.end = Math.max(previous.end, safeEnd);
    return;
  }
  ranges.push({ start: safeStart, end: safeEnd });
};

const resolveDebugRawSpan = (
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number
): FileRange | null => {
  if (dataSize <= 0) return null;
  const start = pointerToRawDataOff || (addressOfRawDataRva ? rvaToOff(addressOfRawDataRva) : null);
  if (start == null || start < 0 || start >= fileSize) return null;
  const end = start + dataSize;
  if (end > fileSize) return null;
  return { start, end };
};

const readDebugDirectoryEntry = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  debugDirectoryRva: number,
  index: number,
  addWarning: (message: string | null) => void
): Promise<DataView | null> => {
  const entryRva = debugDirectoryRva + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
  const entryOffset = rvaToOff(entryRva >>> 0);
  if (entryOffset == null || entryOffset < 0) {
    addWarning("Debug directory no longer maps through rvaToOff.");
    return null;
  }
  if (entryOffset + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE > reader.size) {
    addWarning("Debug directory extends beyond end of file (possible truncation).");
    return null;
  }
  const view = await reader.read(entryOffset, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  if (view.byteLength < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
    addWarning("Debug directory entry is truncated.");
    return null;
  }
  return view;
};

const decodeDebugDirectoryEntry = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  view: DataView,
  machine: number,
  addWarning: (message: string | null) => void,
  rawDataRanges: FileRange[]
): Promise<PeDebugDirectoryEntry> => {
  const characteristics = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_CHARACTERISTICS, true);
  if (characteristics !== 0) {
    addWarning("Debug directory entry Characteristics field is non-zero; the PE format reserves it as 0.");
  }
  const type = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_TYPE, true);
  const dataSize = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_SIZE_OF_DATA, true);
  const addressOfRawDataRva = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_ADDRESS_OF_RAW_DATA, true);
  const pointerToRawDataOff = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_POINTER_TO_RAW_DATA, true);
  const rawDataRange = resolveDebugRawSpan(reader.size, rvaToOff, addressOfRawDataRva, pointerToRawDataOff, dataSize);
  if (rawDataRange) appendFileRange(rawDataRanges, rawDataRange.start, rawDataRange.end, reader.size);
  const currentEntry: PeDebugDirectoryEntry = {
    characteristics,
    type,
    typeName: DEBUG_TYPE_NAMES[type] || `TYPE_${type}`,
    sizeOfData: dataSize,
    addressOfRawData: addressOfRawDataRva,
    pointerToRawData: pointerToRawDataOff
  };
  Object.assign(
    currentEntry,
    await decodeDebugEntryPayload(
      reader,
      {
        type,
        typeName: currentEntry.typeName,
        fileSize: reader.size,
        rvaToOff,
        addressOfRawDataRva,
        pointerToRawDataOff,
        dataSize,
        machine
      },
      addWarning
    )
  );
  return currentEntry;
};

export async function parseDebugDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  machine: number
): Promise<{
  entry: PeCodeViewEntry | null;
  entries: PeDebugDirectoryEntry[];
  warning: string | null;
  rawDataRanges: FileRange[];
}> {
  const warnings: string[] = [];
  const addWarning = (message: string | null): void => {
    if (message && !warnings.includes(message)) warnings.push(message);
  };
  const debugDir = dataDirs.find(d => d.name === "DEBUG");
  if (!debugDir || (debugDir.rva === 0 && debugDir.size === 0)) {
    return { entry: null, entries: [], warning: null, rawDataRanges: [] };
  }
  if (debugDir.rva === 0) {
    return {
      entry: null,
      entries: [],
      warning: "Debug directory has a non-zero size but RVA is 0.",
      rawDataRanges: []
    };
  }
  if (debugDir.size === 0) {
    return {
      entry: null,
      entries: [],
      warning: "Debug directory has an RVA but size is 0.",
      rawDataRanges: []
    };
  }
  const baseOffset = rvaToOff(debugDir.rva);
  if (baseOffset == null || baseOffset < 0) {
    return {
      entry: null,
      entries: [],
      warning: "Debug directory RVA does not map to a file offset.",
      rawDataRanges: []
    };
  }
  const fileSize = reader.size;
  if (baseOffset >= fileSize) {
    return { entry: null, entries: [], warning: "Debug directory starts past end of file.", rawDataRanges: [] };
  }
  const availableDirSize = Math.min(debugDir.size, Math.max(0, fileSize - baseOffset));
  if (availableDirSize < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
    return {
      entry: null,
      entries: [],
      warning: "Debug directory is smaller than one entry; file may be truncated.",
      rawDataRanges: []
    };
  }
  const maxEntries = Math.floor(availableDirSize / IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const rawDataRanges: FileRange[] = [];
  const entries: PeDebugDirectoryEntry[] = [];
  let entry: PeCodeViewEntry | null = null;
  addWarning(
    availableDirSize < debugDir.size
      ? "Debug directory is shorter than recorded size (possible truncation)."
      : null
  );
  if (availableDirSize % IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE !== 0) {
    addWarning("Debug directory size has trailing bytes after whole entries.");
  }
  for (let index = 0; index < maxEntries; index++) {
    const view = await readDebugDirectoryEntry(reader, rvaToOff, debugDir.rva, index, addWarning);
    if (!view) break;
    const currentEntry = await decodeDebugDirectoryEntry(reader, rvaToOff, view, machine, addWarning, rawDataRanges);
    if (currentEntry.codeView && !entry) entry = currentEntry.codeView;
    entries.push(currentEntry);
  }
  return {
    entry,
    entries,
    warning: warnings.length ? warnings.join(" | ") : null,
    rawDataRanges
  };
}
