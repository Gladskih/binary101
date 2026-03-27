"use strict";

import { toHex32 } from "../../binary-utils.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";
import { createPeRangeReader } from "./range-reader.js";
import { readMappedNullTerminatedAsciiString } from "./mapped-ascii-string.js";

// PE/COFF: IMAGE_DEBUG_DIRECTORY entry layout (28 bytes, file form):
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

// CodeView RSDS header is at least 24 bytes: signature (4) + GUID (16) + age (4).
const CODEVIEW_RSDS_MIN_SIZE = 24;
const CODEVIEW_SIGNATURE_RSDS = 0x53445352; // "RSDS" as a little-endian uint32

const CODEVIEW_PATH_READ_CHUNK_SIZE = 64;

type FileRange = { start: number; end: number };

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
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<{
  entry: { guid: string; age: number; path: string } | null;
  warning: string | null;
  rawDataRanges: FileRange[];
}> {
  const warnings: string[] = [];
  const addWarning = (message: string | null): void => {
    if (message && !warnings.includes(message)) warnings.push(message);
  };
  const debugDir = dataDirs.find(d => d.name === "DEBUG");
  if (!debugDir?.rva) return { entry: null, warning: null, rawDataRanges: [] };
  const baseOffset = rvaToOff(debugDir.rva);
  if (baseOffset == null || baseOffset < 0) {
    return {
      entry: null,
      warning: "Debug directory RVA does not map to a file offset.",
      rawDataRanges: []
    };
  }
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (baseOffset >= fileSize) {
    return { entry: null, warning: "Debug directory starts past end of file.", rawDataRanges: [] };
  }
  const availableDirSize = Math.min(debugDir.size, Math.max(0, fileSize - baseOffset));
  const reader = createPeRangeReader(file, 0, file.size);
  if (availableDirSize < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
    return {
      entry: null,
      warning: "Debug directory is smaller than one entry; file may be truncated.",
      rawDataRanges: []
    };
  }
  const maxEntries = Math.floor(availableDirSize / IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const rawDataRanges: FileRange[] = [];
  let entry: { guid: string; age: number; path: string } | null = null;
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
    const view = new DataView(
      await file.slice(entryOffset, entryOffset + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE).arrayBuffer()
    );
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

    if (type !== IMAGE_DEBUG_TYPE_CODEVIEW || entry) continue;
    if (dataSize < CODEVIEW_RSDS_MIN_SIZE) {
      addWarning("CodeView debug entry is smaller than the minimum RSDS header.");
      continue;
    }

    const dataOffset = pointerToRawDataOff
      ? pointerToRawDataOff
      : addressOfRawDataRva
        ? rvaToOff(addressOfRawDataRva)
        : null;
    if (dataOffset == null || dataOffset < 0) {
      addWarning(pointerToRawDataOff || addressOfRawDataRva
        ? "CodeView debug entry does not map to file data (check PointerToRawData/AddressOfRawData)."
        : "CodeView debug entry has no PointerToRawData/AddressOfRawData.");
      continue;
    }

    const dataEnd = dataOffset + dataSize;
    if (dataOffset >= fileSize || dataEnd > fileSize) {
      addWarning("Debug directory points outside file bounds; file may be malformed.");
      continue;
    }

    const header = new DataView(await file.slice(dataOffset, dataOffset + CODEVIEW_RSDS_MIN_SIZE).arrayBuffer());
    if (header.getUint32(0, true) !== CODEVIEW_SIGNATURE_RSDS) continue;
    const sig0 = header.getUint32(4, true);
    const sig1 = header.getUint16(8, true);
    const sig2 = header.getUint16(10, true);
    const sigTail = new Uint8Array(await file.slice(dataOffset + 12, dataOffset + 20).arrayBuffer());
    const guid =
      `${toHex32(sig0, 8).slice(2)}-${sig1.toString(16).padStart(4, "0")}-${sig2.toString(16).padStart(4, "0")}-` +
      `${[...sigTail.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-` +
      `${[...sigTail.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
    const age = header.getUint32(20, true);
    let path = "";
    const pathByteLength = dataSize - CODEVIEW_RSDS_MIN_SIZE;
    if (pointerToRawDataOff === 0 && addressOfRawDataRva !== 0) {
      const pathInfo = await readMappedNullTerminatedAsciiString(
        reader,
        fileSize,
        rvaToOff,
        (addressOfRawDataRva + CODEVIEW_RSDS_MIN_SIZE) >>> 0,
        pathByteLength,
        CODEVIEW_PATH_READ_CHUNK_SIZE
      );
      if (pathInfo) {
        path = pathInfo.text;
        if (!pathInfo.terminated) {
          addWarning("CodeView RSDS path is not NUL-terminated within SizeOfData.");
        }
      } else {
        addWarning("CodeView RSDS path does not map to file data.");
      }
    } else {
      let pos = dataOffset + CODEVIEW_RSDS_MIN_SIZE;
      const pathEnd = dataOffset + dataSize;
      while (pos < pathEnd) {
        const chunkLength = Math.min(CODEVIEW_PATH_READ_CHUNK_SIZE, pathEnd - pos);
        const chunk = new Uint8Array(await file.slice(pos, pos + chunkLength).arrayBuffer());
        const zeroIndex = chunk.indexOf(0);
        if (zeroIndex === -1) {
          path += String.fromCharCode(...chunk);
          pos += chunkLength;
        } else {
          if (zeroIndex > 0) path += String.fromCharCode(...chunk.slice(0, zeroIndex));
          break;
        }
      }
      if (pos >= pathEnd) {
        addWarning("CodeView RSDS path is not NUL-terminated within SizeOfData.");
      }
    }
    entry = { guid, age, path };
  }
  return { entry, warning: warnings.length ? warnings.join(" | ") : null, rawDataRanges };
}
