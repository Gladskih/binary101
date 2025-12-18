"use strict";

import { toHex32 } from "../../binary-utils.js";
import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

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

// Guard against degenerate/malicious files with huge debug directory sizes.
const MAX_DEBUG_DIRECTORY_ENTRIES = 16;

// PE/COFF: IMAGE_DEBUG_TYPE_CODEVIEW
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;

// CodeView RSDS header is at least 24 bytes: signature (4) + GUID (16) + age (4).
const CODEVIEW_RSDS_MIN_SIZE = 24;
const CODEVIEW_SIGNATURE_RSDS = 0x53445352; // "RSDS" as a little-endian uint32

// Keep path parsing bounded even if the string is not NUL-terminated.
const CODEVIEW_PATH_MAX_BYTES = 1024;
const CODEVIEW_PATH_READ_CHUNK_SIZE = 64;

export async function parseDebugDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{ entry: { guid: string; age: number; path: string } | null; warning: string | null }> {
  const debugDir = dataDirs.find(d => d.name === "DEBUG");
  if (!debugDir?.rva || debugDir.size < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) return { entry: null, warning: null };
  const baseOffset = rvaToOff(debugDir.rva);
  if (baseOffset == null) return { entry: null, warning: "Debug directory RVA does not map to a file offset." };
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (baseOffset >= fileSize) return { entry: null, warning: "Debug directory starts past end of file." };
  const availableDirSize = Math.min(debugDir.size, Math.max(0, fileSize - baseOffset));
  addCoverageRegion("DEBUG directory", baseOffset, availableDirSize);
  const maxEntries =
    Math.min(MAX_DEBUG_DIRECTORY_ENTRIES, Math.floor(availableDirSize / IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE));
  if (maxEntries === 0) {
    return { entry: null, warning: "Debug directory is smaller than one entry; file may be truncated." };
  }
  let warning = availableDirSize < debugDir.size ? "Debug directory is shorter than recorded size (possible truncation)." : null;
  let codeViewMappingWarning: string | null = null;
  for (let index = 0; index < maxEntries; index++) {
    const entryOffset = baseOffset + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
    if (entryOffset + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE > fileSize) {
      warning ??= "Debug directory extends beyond end of file (possible truncation).";
      break;
    }
    const view = new DataView(
      await file.slice(entryOffset, entryOffset + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE).arrayBuffer()
    );
    if (view.byteLength < IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
      warning ??= "Debug directory entry is truncated.";
      break;
    }

    const type = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_TYPE, true);
    const dataSize = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_SIZE_OF_DATA, true);
    const addressOfRawDataRva = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_ADDRESS_OF_RAW_DATA, true);
    const pointerToRawDataOff = view.getUint32(IMAGE_DEBUG_DIRECTORY_OFF_POINTER_TO_RAW_DATA, true);

    if (type !== IMAGE_DEBUG_TYPE_CODEVIEW) continue;
    if (dataSize < CODEVIEW_RSDS_MIN_SIZE) continue;

    const dataOffset = pointerToRawDataOff
      ? pointerToRawDataOff
      : addressOfRawDataRva
        ? rvaToOff(addressOfRawDataRva)
        : null;
    if (dataOffset == null || dataOffset < 0) {
      codeViewMappingWarning ??= pointerToRawDataOff || addressOfRawDataRva
        ? "CodeView debug entry does not map to file data (check PointerToRawData/AddressOfRawData)."
        : "CodeView debug entry has no PointerToRawData/AddressOfRawData.";
      continue;
    }

    const dataEnd = dataOffset + dataSize;
    if (dataOffset >= fileSize || dataEnd > fileSize) {
      warning ??= "Debug directory points outside file bounds; file may be malformed.";
      continue;
    }

    const header = new DataView(await file.slice(dataOffset, dataOffset + dataSize).arrayBuffer());
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
    let pos = dataOffset + CODEVIEW_RSDS_MIN_SIZE;
    while (pos < dataOffset + dataSize && path.length < CODEVIEW_PATH_MAX_BYTES) {
      const chunk = new Uint8Array(await file.slice(pos, pos + CODEVIEW_PATH_READ_CHUNK_SIZE).arrayBuffer());
      const zeroIndex = chunk.indexOf(0);
      if (zeroIndex === -1) {
        path += String.fromCharCode(...chunk);
        pos += CODEVIEW_PATH_READ_CHUNK_SIZE;
      } else {
        if (zeroIndex > 0) path += String.fromCharCode(...chunk.slice(0, zeroIndex));
        break;
      }
    }
    return { entry: { guid, age, path }, warning };
  }
  warning ??= codeViewMappingWarning;
  return { entry: null, warning };
}
