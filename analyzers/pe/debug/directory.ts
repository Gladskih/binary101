"use strict";

import { contiguousRvaOffset, mappedRvaSize } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeCodeViewEntry } from "./codeview.js";
import { decodeDebugEntryPayload, type PeDebugPayloads } from "./entry-decoders.js";
import { DEBUG_TYPE_NAMES } from "./types.js";
import type { PeDataDirectory, PeWindowsOptionalHeader, RvaToOffset } from "../types.js";
import { validateDebugEntry, validatePortablePdbLinks } from "./entry-validation.js";
import { directHllDirectory } from "./codeview-location.js";

export type { PeCodeViewEntry } from "./codeview.js";
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
// - TimeDateStamp (DWORD) at +0x04
// - MajorVersion and MinorVersion (WORD each) at +0x08 and +0x0a
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
  timeDateStamp: number;
  majorVersion: number;
  minorVersion: number;
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
  ranges.push({ start: safeStart, end: safeEnd });
};

const mergeFileRanges = (ranges: FileRange[]): FileRange[] => {
  const merged: FileRange[] = [];
  for (const range of ranges.sort((left, right) => left.start - right.start)) {
    const previous = merged.at(-1);
    if (previous && range.start <= previous.end) previous.end = Math.max(previous.end, range.end);
    else merged.push(range);
  }
  return merged;
};

const resolveDebugRawSpan = (
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number
): FileRange | null => {
  if (dataSize <= 0) return null;
  const start = pointerToRawDataOff || (addressOfRawDataRva
    ? contiguousRvaOffset(rvaToOff, addressOfRawDataRva, dataSize, fileSize) : null);
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
  const entryOffset = rvaToOff(entryRva);
  if (entryOffset == null || entryOffset < 0) {
    addWarning("Debug directory no longer maps through rvaToOff.");
    return null;
  }
  const view = await readMappedRvaPrefix(reader, entryRva, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE, rvaToOff);
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
  rawDataRanges: FileRange[],
  exceptionDirectory: PeDataDirectory | undefined,
  header: PeWindowsOptionalHeader | undefined
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
    timeDateStamp: view.getUint32(0x04, true),
    majorVersion: view.getUint16(0x08, true),
    minorVersion: view.getUint16(0x0a, true),
    type,
    typeName: DEBUG_TYPE_NAMES[type] || `TYPE_${type}`,
    sizeOfData: dataSize,
    addressOfRawData: addressOfRawDataRva,
    pointerToRawData: pointerToRawDataOff
  };
  Object.assign(currentEntry, await decodeDebugEntryPayload(reader, {
    type, typeName: currentEntry.typeName, fileSize: reader.size, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, machine, exceptionDirectory, header
  }, addWarning));
  validateDebugEntry(currentEntry, rvaToOff, reader.size).forEach(addWarning);
  return currentEntry;
};

const findDebugDirectory = (
  dataDirs: PeDataDirectory[], addWarning: (message: string | null) => void
): PeDataDirectory | null => {
  const directory = dataDirs.find(item => item.name === "DEBUG");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  if (directory.rva === 0) {
    addWarning("Debug directory has a non-zero size but RVA is 0.");
    return null;
  }
  if (directory.size === 0) {
    addWarning("Debug directory has an RVA but size is 0.");
    return null;
  }
  return directory;
};

const readableDebugEntryCount = (
  fileSize: number, debugDir: PeDataDirectory, rvaToOff: RvaToOffset,
  addWarning: (message: string | null) => void
): number => {
  const baseOffset = rvaToOff(debugDir.rva);
  if (baseOffset == null || baseOffset < 0) {
    addWarning("Debug directory RVA does not map to a file offset.");
    return 0;
  }
  if (baseOffset >= fileSize) {
    addWarning("Debug directory starts past end of file.");
    return 0;
  }
  const availableDirSize = mappedRvaSize(rvaToOff, debugDir.rva, debugDir.size, fileSize);
  if (availableDirSize < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
    addWarning("Debug directory is smaller than one entry; file may be truncated.");
    return 0;
  }
  addWarning(
    availableDirSize < debugDir.size
      ? "Debug directory is shorter than recorded size (possible truncation)."
      : null
  );
  if (availableDirSize % IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE !== 0) {
    addWarning("Debug directory size has trailing bytes after whole entries.");
  }
  return Math.floor(availableDirSize / IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
};

export async function parseDebugDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  machine: number,
  header?: PeWindowsOptionalHeader
): Promise<{
  entry: PeCodeViewEntry | null;
  entries: PeDebugDirectoryEntry[];
  warning: string | null;
  rawDataRanges: FileRange[];
}> {
  const warnings = new Set<string>();
  const addWarning = (message: string | null): void => {
    if (message) warnings.add(message);
  };
  const debugDir = findDebugDirectory(dataDirs, addWarning);
  if (!debugDir) return { entry: null, entries: [],
    warning: warnings.size ? [...warnings].join(" | ") : null, rawDataRanges: [] };
  if (await directHllDirectory(reader, debugDir, rvaToOff, message => addWarning(message))) {
    return { entry: null, entries: [], warning: null, rawDataRanges: [] };
  }
  const maxEntries = readableDebugEntryCount(reader.size, debugDir, rvaToOff, addWarning);
  const rawDataRanges: FileRange[] = [];
  const exceptionDirectory = dataDirs.find(directory => directory.name === "EXCEPTION");
  const entries: PeDebugDirectoryEntry[] = [];
  let entry: PeCodeViewEntry | null = null;
  for (let index = 0; index < maxEntries; index++) {
    const view = await readDebugDirectoryEntry(reader, rvaToOff, debugDir.rva, index, addWarning);
    if (!view) break;
    const currentEntry = await decodeDebugDirectoryEntry(reader, rvaToOff, view, machine,
      message => addWarning(message ? `Debug entry #${index + 1}: ${message}` : null), rawDataRanges,
      exceptionDirectory, header);
    if (currentEntry.codeView && !entry) entry = currentEntry.codeView;
    entries.push(currentEntry);
  }
  validatePortablePdbLinks(entries).forEach(addWarning);
  return {
    entry,
    entries,
    warning: warnings.size ? [...warnings].join(" | ") : null,
    rawDataRanges: mergeFileRanges(rawDataRanges)
  };
}
