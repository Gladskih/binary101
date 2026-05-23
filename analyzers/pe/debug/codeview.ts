"use strict";

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

export const parseCodeViewEntry = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeCodeViewEntry | null> => {
  if (dataSize < CODEVIEW_NB10_MIN_SIZE) {
    addWarning("CodeView debug entry is smaller than the minimum NB10 header.");
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
  const header = await reader.read(dataOffset, Math.min(dataSize, CODEVIEW_RSDS_MIN_SIZE));
  if (header.byteLength < CODEVIEW_NB10_MIN_SIZE) {
    addWarning("CodeView debug entry is truncated before the full NB10 header.");
    return null;
  }
  const signature = header.getUint32(0, true);
  if (signature === CODEVIEW_SIGNATURE_NB10) {
    return {
      signature: "NB10",
      offset: header.getUint32(CODEVIEW_NB10_OFF_OFFSET, true),
      timestamp: header.getUint32(CODEVIEW_NB10_OFF_TIMESTAMP, true),
      age: header.getUint32(CODEVIEW_NB10_OFF_AGE, true),
      path: await readCodeViewPathFromFilePointer(
        reader,
        dataOffset,
        dataSize,
        CODEVIEW_NB10_MIN_SIZE,
        addWarning
      )
    };
  }
  if (signature !== CODEVIEW_SIGNATURE_RSDS) {
    addWarning("CodeView debug entry signature is not RSDS or NB10.");
    return null;
  }
  if (header.byteLength < CODEVIEW_RSDS_MIN_SIZE) {
    addWarning("CodeView debug entry is truncated before the full RSDS header.");
    return null;
  }
  const sig0 = header.getUint32(CODEVIEW_RSDS_OFF_GUID_DATA1, true);
  const sig1 = header.getUint16(CODEVIEW_RSDS_OFF_GUID_DATA2, true);
  const sig2 = header.getUint16(CODEVIEW_RSDS_OFF_GUID_DATA3, true);
  const sigTail = await reader.readBytes(
    dataOffset + CODEVIEW_RSDS_OFF_GUID_DATA4,
    CODEVIEW_RSDS_GUID_DATA4_LENGTH
  );
  const guid =
    `${toHex32(sig0, 8).slice(2)}-${sig1.toString(16).padStart(4, "0")}-${sig2.toString(16).padStart(4, "0")}-` +
    `${[...sigTail.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-` +
    `${[...sigTail.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
  const age = header.getUint32(CODEVIEW_RSDS_OFF_AGE, true);
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
      : await readCodeViewPathFromFilePointer(
          reader,
          dataOffset,
          dataSize,
          CODEVIEW_RSDS_MIN_SIZE,
          addWarning
        );
  return { signature: "RSDS", guid, age, path };
};
