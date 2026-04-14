"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseCodeViewEntry, type PeCodeViewEntry } from "./codeview.js";
import { parsePogoInfo, type PePogoInfo } from "./pogo.js";
import { parseVcFeatureInfo, type PeVcFeatureInfo } from "./vc-feature.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

export type { PeCodeViewEntry } from "./codeview.js";
export type { PePogoEntry, PePogoInfo } from "./pogo.js";
export type { PeVcFeatureInfo } from "./vc-feature.js";

// Microsoft PE format, "Debug Directory (Image Only)":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
// IMAGE_DEBUG_DIRECTORY entry layout (28 bytes, file form):
// - Type (DWORD) at +0x0c
// - SizeOfData (DWORD) at +0x10
// - AddressOfRawData (DWORD, RVA) at +0x14
// - PointerToRawData (DWORD, file offset) at +0x18
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
const IMAGE_DEBUG_DIRECTORY_OFF_TYPE = 0x0c;
const IMAGE_DEBUG_DIRECTORY_OFF_SIZE_OF_DATA = 0x10;
const IMAGE_DEBUG_DIRECTORY_OFF_ADDRESS_OF_RAW_DATA = 0x14;
const IMAGE_DEBUG_DIRECTORY_OFF_POINTER_TO_RAW_DATA = 0x18;

// PE/COFF: IMAGE_DEBUG_TYPE_CODEVIEW
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const IMAGE_DEBUG_TYPE_VC_FEATURE = 12;
const IMAGE_DEBUG_TYPE_POGO = 13;

const DEBUG_TYPE_NAMES: Record<number, string> = {
  0: "UNKNOWN",
  1: "COFF",
  2: "CODEVIEW",
  3: "FPO",
  4: "MISC",
  5: "EXCEPTION",
  6: "FIXUP",
  7: "OMAP_TO_SRC",
  8: "OMAP_FROM_SRC",
  9: "BORLAND",
  10: "RESERVED10",
  11: "CLSID",
  12: "VC_FEATURE",
  13: "POGO",
  14: "ILTCG",
  15: "MPX",
  16: "REPRO",
  17: "EMBEDDED DEBUG",
  19: "SYMBOL HASH",
  20: "EX_DLLCHARACTERISTICS"
};

type FileRange = { start: number; end: number };

export interface PeDebugDirectoryEntry {
  type: number;
  typeName: string;
  sizeOfData: number;
  addressOfRawData: number;
  pointerToRawData: number;
  codeView?: PeCodeViewEntry;
  vcFeature?: PeVcFeatureInfo;
  pogo?: PePogoInfo;
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

export async function parseDebugDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
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
  if (!debugDir?.rva) return { entry: null, entries: [], warning: null, rawDataRanges: [] };
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
    const entryRva = debugDir.rva + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
    const entryOffset = rvaToOff(entryRva >>> 0);
    if (entryOffset == null || entryOffset < 0) {
      addWarning("Debug directory no longer maps through rvaToOff.");
      break;
    }
    if (entryOffset + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE > fileSize) {
      addWarning("Debug directory extends beyond end of file (possible truncation).");
      break;
    }
    const view = await reader.read(entryOffset, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
    if (view.byteLength < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
      addWarning("Debug directory entry is truncated.");
      break;
    }

    const type = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_TYPE, true);
    const dataSize = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_SIZE_OF_DATA, true);
    const addressOfRawDataRva = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_ADDRESS_OF_RAW_DATA, true);
    const pointerToRawDataOff = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_POINTER_TO_RAW_DATA, true);
    const rawDataRange = resolveDebugRawSpan(
      fileSize,
      rvaToOff,
      addressOfRawDataRva,
      pointerToRawDataOff,
      dataSize
    );
    if (rawDataRange) {
      appendFileRange(rawDataRanges, rawDataRange.start, rawDataRange.end, fileSize);
    }

    const currentEntry: PeDebugDirectoryEntry = {
      type,
      typeName: DEBUG_TYPE_NAMES[type] || `TYPE_${type}`,
      sizeOfData: dataSize,
      addressOfRawData: addressOfRawDataRva,
      pointerToRawData: pointerToRawDataOff
    };
    if (type === IMAGE_DEBUG_TYPE_CODEVIEW) {
      const codeView = await parseCodeViewEntry(
        reader,
        fileSize,
        rvaToOff,
        addressOfRawDataRva,
        pointerToRawDataOff,
        dataSize,
        addWarning
      );
      if (codeView) {
        currentEntry.codeView = codeView;
        if (!entry) entry = codeView;
      }
    }
    if (type === IMAGE_DEBUG_TYPE_VC_FEATURE) {
      const vcFeature = await parseVcFeatureInfo(
        reader,
        fileSize,
        rvaToOff,
        addressOfRawDataRva,
        pointerToRawDataOff,
        dataSize,
        addWarning
      );
      if (vcFeature) currentEntry.vcFeature = vcFeature;
    }
    if (type === IMAGE_DEBUG_TYPE_POGO) {
      const pogo = await parsePogoInfo(
        reader,
        fileSize,
        rvaToOff,
        addressOfRawDataRva,
        pointerToRawDataOff,
        dataSize,
        addWarning
      );
      if (pogo) currentEntry.pogo = pogo;
    }
    entries.push(currentEntry);
  }
  return {
    entry,
    entries,
    warning: warnings.length ? warnings.join(" | ") : null,
    rawDataRanges
  };
}
