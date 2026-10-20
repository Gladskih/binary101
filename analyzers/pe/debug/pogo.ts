"use strict";

import { readDebugPayload } from "./payload-reader.js";
import { getReadableDebugData } from "./data.js";
import { alignUpTo, readAsciiString, toHex32 } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";

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
  0x50475500: "PGU",
  // Visual Studio 18 dumpbin /HEADERS reports 0x5350474F as "(SPGO)".
  0x5350474f: "SPGO"
};

// Upstream parsers model each POGO record as start_rva + size + NUL-terminated name.
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const POGO_OFF_SIGNATURE = 0;
const POGO_HEADER_SIZE = 4;
const POGO_ENTRY_OFF_START_RVA = 0;
const POGO_ENTRY_OFF_SIZE = 4;
const POGO_ENTRY_NAME_OFFSET = 8;
const POGO_ENTRY_PREFIX_SIZE = 8;

const getPogoSignatureName = (signature: number): string =>
  POGO_SIGNATURE_NAMES[signature >>> 0] ?? `UNKNOWN_${toHex32(signature, 8)}`;

type PogoPayloadReader = (offset: number, size: number) => Promise<DataView>;

const readPogoName = async (read: PogoPayloadReader, offset: number, size: number) => {
  const parts: string[] = [];
  // Chunk size controls I/O granularity, never the accepted name length.
  for (let cursor = offset; cursor < size; cursor += 64) {
    const count = Math.min(64, size - cursor);
    const view = await read(cursor, count);
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const zero = bytes.indexOf(0);
    parts.push(readAsciiString(view, 0, zero < 0 ? bytes.length : zero));
    if (zero >= 0) return { name: parts.join(""), end: cursor + zero + 1 };
    if (view.byteLength < count) break;
  }
  return null;
};

const readPogoEntries = async (
  read: PogoPayloadReader, size: number, addWarning: (message: string) => void
): Promise<PePogoEntry[]> => {
  const entries: PePogoEntry[] = [];
  let cursor = POGO_HEADER_SIZE;
  while (cursor < size) {
    const view = await read(cursor, Math.min(POGO_ENTRY_PREFIX_SIZE, size - cursor));
    if (view.byteLength < POGO_ENTRY_PREFIX_SIZE) {
      addWarning("POGO payload has trailing bytes after whole entries.");
      break;
    }
    const name = await readPogoName(read, cursor + POGO_ENTRY_NAME_OFFSET, size);
    if (!name) {
      addWarning("POGO entry name is not NUL-terminated within SizeOfData.");
      break;
    }
    const startRva = view.getUint32(POGO_ENTRY_OFF_START_RVA, true);
    const regionSize = view.getUint32(POGO_ENTRY_OFF_SIZE, true);
    if (startRva + regionSize > 0x100000000) addWarning("POGO region extends beyond the 32-bit RVA space.");
    entries.push({ startRva, size: regionSize, name: name.name });
    cursor = alignUpTo(name.end, 4);
    if (cursor > size) addWarning("POGO final record alignment padding is truncated.");
  }
  return entries;
};

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
    "POGO", fileSize,
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
  const read: PogoPayloadReader = (offset, size) => readDebugPayload(
    reader, rvaToOff, addressOfRawDataRva, pointerToRawDataOff, offset, size);
  const view = await read(0, POGO_HEADER_SIZE);
  if (view.byteLength < POGO_HEADER_SIZE) {
    addWarning("POGO signature header is truncated while reading.");
    return null;
  }
  const signature = view.getUint32(POGO_OFF_SIGNATURE, true);
  const signatureName = getPogoSignatureName(signature);
  const entries: PePogoEntry[] = [];
  if (!(signature in POGO_SIGNATURE_NAMES)) {
    addWarning(`POGO signature ${toHex32(signature, 8)} is not recognized; entry list not decoded.`);
    return { signature, signatureName, entries };
  }
  return { signature, signatureName, entries: await readPogoEntries(read, dataInfo.size, addWarning) };
};
