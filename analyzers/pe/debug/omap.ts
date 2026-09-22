"use strict";

import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../../file-range-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";

export interface PeOmapRecord {
  rva: number;
  rvaTo: number;
}

export interface PeOmapInfo {
  records: PeOmapRecord[];
}

// OMAP is a sorted array of two little-endian ULONGs, with no header.
// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
const OMAP_RECORD_SIZE = 8;

const appendOmapRecords = (
  view: DataView, records: PeOmapRecord[], warnings: Set<string>
): void => {
  for (let offset = 0; offset + OMAP_RECORD_SIZE <= view.byteLength; offset += OMAP_RECORD_SIZE) {
    const rva = view.getUint32(offset, true);
    const previous = records.at(-1);
    if (previous && rva <= previous.rva) {
      warnings.add("OMAP input RVAs are not strictly increasing; mapping is ambiguous.");
    }
    // The second ULONG starts four bytes after the input RVA (OMAP definition above).
    records.push({ rva, rvaTo: view.getUint32(offset + 4, true) });
  }
};

export const parseOmapInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeOmapInfo | null> => {
  if (![addressOfRawDataRva, pointerToRawDataOff, dataSize].every(value =>
    Number.isSafeInteger(value) && value >= 0 && value < PE_RVA_EXCLUSIVE_LIMIT)) {
    addWarning("OMAP debug entry has an invalid offset or size.");
    return null;
  }
  if (dataSize === 0) {
    addWarning("OMAP debug entry is empty.");
    return { records: [] };
  }
  const dataInfo = getReadableDebugData("OMAP", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!dataInfo) return null;
  if (dataInfo.size % OMAP_RECORD_SIZE !== 0) {
    addWarning("OMAP debug entry has trailing bytes after whole records.");
  }
  const records: PeOmapRecord[] = [];
  const warnings = new Set<string>();
  const readableSize = Math.floor(dataInfo.size / OMAP_RECORD_SIZE) * OMAP_RECORD_SIZE;
  for (let offset = 0; offset < readableSize; offset += DEFAULT_FILE_READ_WINDOW_BYTES) {
    const size = Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, readableSize - offset);
    const view = await readDebugPayload(reader, rvaToOff,
      addressOfRawDataRva, pointerToRawDataOff, offset, size);
    appendOmapRecords(view, records, warnings);
    if (view.byteLength < size) {
      warnings.add("OMAP debug payload is truncated while reading records.");
      break;
    }
  }
  warnings.forEach(addWarning);
  return { records };
};
