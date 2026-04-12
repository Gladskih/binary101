"use strict";

import { alignUpTo, readAsciiString, toHex32 } from "../../binary-utils.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { RvaToOffset } from "./types.js";

export interface PePogoEntry {
  startRva: number;
  size: number;
  name: string;
}

export interface PePogoInfo {
  signature: number;
  signatureName: string;
  entries: PePogoEntry[];
}

// Upstream PE parsers recognize these POGO signatures:
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
// LIEF exposes ZERO, LTCG/LCTG, and PGI as the same debug structure family:
// https://lief.re/doc/stable/formats/pe/cpp.html#_CPPv4N4LIEF2PE4Pogo10SIGNATURESE
const POGO_SIGNATURE_NAMES: Record<number, string> = {
  0x00000000: "ZERO",
  0x4c544347: "LTCG",
  0x50474900: "PGI",
  0x50474f00: "PGO",
  0x50475500: "PGU"
};

// Upstream parsers model each POGO record as start_rva + size + NUL-terminated name.
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const POGO_OFF_SIGNATURE = 0;
const POGO_HEADER_SIZE = 4;
const POGO_ENTRY_OFF_START_RVA = 0;
const POGO_ENTRY_OFF_SIZE = 4;
const POGO_ENTRY_NAME_OFFSET = 8;
const POGO_ENTRY_PREFIX_SIZE = 8;

const getReadableDebugData = (
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): { offset: number; size: number } | null => {
  const offset = pointerToRawDataOff || (
    addressOfRawDataRva ? rvaToOff(addressOfRawDataRva) : null
  );
  if (offset == null || offset < 0) {
    addWarning(
      pointerToRawDataOff || addressOfRawDataRva
        ? "POGO debug entry does not map to file data."
        : "POGO debug entry has no PointerToRawData/AddressOfRawData."
    );
    return null;
  }
  if (offset >= fileSize) {
    addWarning("POGO debug entry starts past end of file.");
    return null;
  }
  const size = Math.min(dataSize, Math.max(0, fileSize - offset));
  if (size < dataSize) {
    addWarning("POGO debug entry is shorter than its declared SizeOfData.");
  }
  return { offset, size };
};

const getPogoSignatureName = (signature: number): string =>
  POGO_SIGNATURE_NAMES[signature >>> 0] ?? `UNKNOWN_${toHex32(signature, 8)}`;

export const parsePogoInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PePogoInfo | null> => {
  const dataInfo = getReadableDebugData(
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < POGO_HEADER_SIZE) {
    addWarning("POGO debug entry is smaller than the signature header.");
    return null;
  }
  const payload = await reader.readBytes(dataInfo.offset, dataInfo.size);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const signature = view.getUint32(POGO_OFF_SIGNATURE, true);
  const signatureName = getPogoSignatureName(signature);
  const entries: PePogoEntry[] = [];
  if (!(signature in POGO_SIGNATURE_NAMES)) {
    addWarning(`POGO signature ${toHex32(signature, 8)} is not recognized; entry list not decoded.`);
    return { signature, signatureName, entries };
  }
  let cursor = POGO_HEADER_SIZE;
  while (cursor < view.byteLength) {
    if (view.byteLength - cursor < POGO_ENTRY_PREFIX_SIZE) {
      addWarning("POGO payload has trailing bytes after whole entries.");
      break;
    }
    const startRva = view.getUint32(cursor + POGO_ENTRY_OFF_START_RVA, true);
    const size = view.getUint32(cursor + POGO_ENTRY_OFF_SIZE, true);
    const nameOffset = cursor + POGO_ENTRY_NAME_OFFSET;
    const zeroIndex = payload.indexOf(0, nameOffset);
    if (zeroIndex === -1) {
      addWarning("POGO entry name is not NUL-terminated within SizeOfData.");
      break;
    }
    entries.push({
      startRva,
      size,
      name: readAsciiString(view, nameOffset, zeroIndex - nameOffset)
    });
    const nextCursor = alignUpTo(zeroIndex + 1, 4);
    if (nextCursor <= cursor) {
      addWarning("POGO entry alignment did not advance.");
      break;
    }
    cursor = nextCursor;
  }
  return { signature, signatureName, entries };
};
