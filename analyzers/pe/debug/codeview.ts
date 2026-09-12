"use strict";

import { readDebugPayload } from "./payload-reader.js";
import { toHex32 } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { RvaToOffset } from "../types.js";

// Microsoft PE/COFF debug data:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
// RSDS CodeView records are:
// signature (4) + GUID (16) + age (4) + NUL-terminated path.
// Legacy NB10 records are documented by dotnet/runtime PE-COFF.md,
// section "CodeView Debug Directory Entry (type 2)".
const CODEVIEW_RSDS_MIN_SIZE = 24;
const CODEVIEW_NB10_MIN_SIZE = 16;
const CODEVIEW_SIGNATURE_RSDS = 0x53445352;
const CODEVIEW_SIGNATURE_NB10 = 0x3031424e;
const CODEVIEW_RSDS_OFF_GUID_DATA1 = 4;
const CODEVIEW_RSDS_OFF_GUID_DATA2 = 8;
const CODEVIEW_RSDS_OFF_GUID_DATA3 = 10;
const CODEVIEW_RSDS_OFF_GUID_DATA4 = 12;
const CODEVIEW_RSDS_GUID_DATA4_LENGTH = 8;
const CODEVIEW_RSDS_OFF_AGE = 20;
const CODEVIEW_NB10_OFF_OFFSET = 4;
const CODEVIEW_NB10_OFF_TIMESTAMP = 8;
const CODEVIEW_NB10_OFF_AGE = 12;
// Implementation detail: bounded 64-byte slices keep path scanning incremental while honoring
// SizeOfData, instead of reading arbitrarily large PDB paths in one go.
const CODEVIEW_PATH_READ_CHUNK_SIZE = 64;

export interface PeCodeViewRsdsEntry {
  signature: "RSDS";
  guid: string;
  age: number;
  path: string;
}

export interface PeCodeViewNb10Entry {
  signature: "NB10";
  offset: number;
  timestamp: number;
  age: number;
  path: string;
}

export type PeCodeViewEntry = PeCodeViewRsdsEntry | PeCodeViewNb10Entry;

const readCodeViewPathFromMappedData = async (
  reader: FileRangeReader,
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
    addressOfRawDataRva,
    pathByteLength,
    CODEVIEW_PATH_READ_CHUNK_SIZE
  );
  if (!pathInfo) {
    addWarning("CodeView path does not map to file data.");
    return "";
  }
  if (!pathInfo.terminated) {
    addWarning("CodeView path is not NUL-terminated within SizeOfData.");
  }
  return pathInfo.text;
};

const readCodeViewPathFromFilePointer = async (
  reader: FileRangeReader,
  dataOffset: number,
  dataSize: number,
  headerSize: number,
  addWarning: (message: string) => void
): Promise<string> => {
  let path = "";
  let pos = dataOffset + headerSize;
  const pathEnd = dataOffset + dataSize;
  while (pos < pathEnd) {
    const chunkLength = Math.min(CODEVIEW_PATH_READ_CHUNK_SIZE, pathEnd - pos);
    const chunk = await reader.readBytes(pos, chunkLength);
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
  addWarning("CodeView path is not NUL-terminated within SizeOfData.");
  return path;
};

const unmappedCodeViewWarning = (address: number): string => address
  ? "CodeView debug entry does not map to file data (check PointerToRawData/AddressOfRawData)."
  : "CodeView debug entry has no PointerToRawData/AddressOfRawData.";

const resolveCodeViewOffset = (
  fileSize: number, rvaToOff: RvaToOffset, addressOfRawDataRva: number,
  pointerToRawDataOff: number, dataSize: number, addWarning: (message: string) => void
): number | null => {
  const dataOffset = pointerToRawDataOff
    ? pointerToRawDataOff
    : addressOfRawDataRva
      ? rvaToOff(addressOfRawDataRva)
      : null;
  if (dataOffset == null || dataOffset < 0) {
    addWarning(unmappedCodeViewWarning(pointerToRawDataOff || addressOfRawDataRva));
    return null;
  }
  if (dataOffset >= fileSize || (pointerToRawDataOff !== 0 && dataOffset + dataSize > fileSize)) {
    addWarning("Debug directory points outside file bounds; file may be malformed.");
    return null;
  }
  return dataOffset;
};

const readCodeViewHeader = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<DataView | null> => {
  if (dataSize < CODEVIEW_NB10_MIN_SIZE) {
    addWarning("CodeView debug entry is smaller than the minimum NB10 header.");
    return null;
  }
  if (resolveCodeViewOffset(fileSize, rvaToOff, addressOfRawDataRva,
    pointerToRawDataOff, dataSize, addWarning) == null) return null;
  const header = await readDebugPayload(reader, rvaToOff, addressOfRawDataRva, pointerToRawDataOff,
    0, Math.min(dataSize, CODEVIEW_RSDS_MIN_SIZE));
  if (header.byteLength < CODEVIEW_NB10_MIN_SIZE) {
    addWarning("CodeView debug entry is truncated before the full NB10 header.");
    return null;
  }
  return header;
};

const readCodeViewGuid = (header: DataView): string => {
  const sig0 = header.getUint32(CODEVIEW_RSDS_OFF_GUID_DATA1, true);
  const sig1 = header.getUint16(CODEVIEW_RSDS_OFF_GUID_DATA2, true);
  const sig2 = header.getUint16(CODEVIEW_RSDS_OFF_GUID_DATA3, true);
  const sigTail = new Uint8Array(header.buffer,
    header.byteOffset + CODEVIEW_RSDS_OFF_GUID_DATA4, CODEVIEW_RSDS_GUID_DATA4_LENGTH);
  return `${toHex32(sig0, 8).slice(2)}-${sig1.toString(16).padStart(4, "0")}-${sig2.toString(16).padStart(4, "0")}-` +
    `${[...sigTail.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-` +
    `${[...sigTail.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
};

export const parseCodeViewEntry = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeCodeViewEntry | null> => {
  const header = await readCodeViewHeader(reader, fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!header) return null;
  const signature = header.getUint32(0, true);
  if (signature !== CODEVIEW_SIGNATURE_RSDS && signature !== CODEVIEW_SIGNATURE_NB10) {
    addWarning("CodeView debug entry signature is not RSDS or NB10.");
    return null;
  }
  const headerSize = signature === CODEVIEW_SIGNATURE_RSDS
    ? CODEVIEW_RSDS_MIN_SIZE : CODEVIEW_NB10_MIN_SIZE;
  if (header.byteLength < headerSize) {
    addWarning("CodeView debug entry is truncated before the full RSDS header.");
    return null;
  }
  const path = pointerToRawDataOff
    ? await readCodeViewPathFromFilePointer(reader, pointerToRawDataOff,
      dataSize, headerSize, addWarning)
    : await readCodeViewPathFromMappedData(reader, fileSize, rvaToOff,
      addressOfRawDataRva + headerSize, dataSize - headerSize, addWarning);
  return signature === CODEVIEW_SIGNATURE_NB10 ? {
    signature: "NB10",
    offset: header.getUint32(CODEVIEW_NB10_OFF_OFFSET, true),
    timestamp: header.getUint32(CODEVIEW_NB10_OFF_TIMESTAMP, true),
    age: header.getUint32(CODEVIEW_NB10_OFF_AGE, true),
    path
  } : {
    signature: "RSDS", guid: readCodeViewGuid(header),
    age: header.getUint32(CODEVIEW_RSDS_OFF_AGE, true), path
  };
};
