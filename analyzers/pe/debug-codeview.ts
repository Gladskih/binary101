"use strict";

import { toHex32 } from "../../binary-utils.js";
import { readMappedNullTerminatedAsciiString } from "./mapped-ascii-string.js";
import type { PeRangeReader } from "./range-reader.js";
import type { RvaToOffset } from "./types.js";

// Microsoft PE/COFF debug data:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const CODEVIEW_RSDS_MIN_SIZE = 24;
const CODEVIEW_SIGNATURE_RSDS = 0x53445352;
const CODEVIEW_PATH_READ_CHUNK_SIZE = 64;

export interface PeCodeViewEntry {
  guid: string;
  age: number;
  path: string;
}

const readCodeViewPathFromMappedData = async (
  reader: PeRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pathByteLength: number,
  addWarning: (message: string) => void
): Promise<string> => {
  const pathInfo = await readMappedNullTerminatedAsciiString(
    reader,
    fileSize,
    rvaToOff,
    (addressOfRawDataRva + CODEVIEW_RSDS_MIN_SIZE) >>> 0,
    pathByteLength,
    CODEVIEW_PATH_READ_CHUNK_SIZE
  );
  if (!pathInfo) {
    addWarning("CodeView RSDS path does not map to file data.");
    return "";
  }
  if (!pathInfo.terminated) {
    addWarning("CodeView RSDS path is not NUL-terminated within SizeOfData.");
  }
  return pathInfo.text;
};

const readCodeViewPathFromFilePointer = async (
  file: File,
  dataOffset: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<string> => {
  let path = "";
  let pos = dataOffset + CODEVIEW_RSDS_MIN_SIZE;
  const pathEnd = dataOffset + dataSize;
  while (pos < pathEnd) {
    const chunkLength = Math.min(CODEVIEW_PATH_READ_CHUNK_SIZE, pathEnd - pos);
    const chunk = new Uint8Array(await file.slice(pos, pos + chunkLength).arrayBuffer());
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex === -1) {
      path += String.fromCharCode(...chunk);
      pos += chunkLength;
      continue;
    }
    if (zeroIndex > 0) {
      path += String.fromCharCode(...chunk.slice(0, zeroIndex));
    }
    return path;
  }
  addWarning("CodeView RSDS path is not NUL-terminated within SizeOfData.");
  return path;
};

export const parseCodeViewEntry = async (
  file: File,
  reader: PeRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeCodeViewEntry | null> => {
  if (dataSize < CODEVIEW_RSDS_MIN_SIZE) {
    addWarning("CodeView debug entry is smaller than the minimum RSDS header.");
    return null;
  }
  const dataOffset = pointerToRawDataOff
    ? pointerToRawDataOff
    : addressOfRawDataRva
      ? rvaToOff(addressOfRawDataRva)
      : null;
  if (dataOffset == null || dataOffset < 0) {
    addWarning(
      pointerToRawDataOff || addressOfRawDataRva
        ? "CodeView debug entry does not map to file data (check PointerToRawData/AddressOfRawData)."
        : "CodeView debug entry has no PointerToRawData/AddressOfRawData."
    );
    return null;
  }
  if (dataOffset >= fileSize || dataOffset + dataSize > fileSize) {
    addWarning("Debug directory points outside file bounds; file may be malformed.");
    return null;
  }
  const header = new DataView(
    await file.slice(dataOffset, dataOffset + CODEVIEW_RSDS_MIN_SIZE).arrayBuffer()
  );
  if (header.byteLength < CODEVIEW_RSDS_MIN_SIZE) {
    addWarning("CodeView debug entry is truncated before the full RSDS header.");
    return null;
  }
  if (header.getUint32(0, true) !== CODEVIEW_SIGNATURE_RSDS) {
    return null;
  }
  const sig0 = header.getUint32(4, true);
  const sig1 = header.getUint16(8, true);
  const sig2 = header.getUint16(10, true);
  const sigTail = new Uint8Array(await file.slice(dataOffset + 12, dataOffset + 20).arrayBuffer());
  const guid =
    `${toHex32(sig0, 8).slice(2)}-${sig1.toString(16).padStart(4, "0")}-${sig2.toString(16).padStart(4, "0")}-` +
    `${[...sigTail.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-` +
    `${[...sigTail.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
  const age = header.getUint32(20, true);
  const pathByteLength = dataSize - CODEVIEW_RSDS_MIN_SIZE;
  const path =
    pointerToRawDataOff === 0 && addressOfRawDataRva !== 0
      ? await readCodeViewPathFromMappedData(
          reader,
          fileSize,
          rvaToOff,
          addressOfRawDataRva,
          pathByteLength,
          addWarning
        )
      : await readCodeViewPathFromFilePointer(file, dataOffset, dataSize, addWarning);
  return { guid, age, path };
};
