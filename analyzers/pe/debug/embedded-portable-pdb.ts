"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readDebugPayload } from "./payload-reader.js";
import { getReadableDebugData } from "./data.js";
import { inflateEmbeddedDebugImage } from "./embedded-debug-image.js";
import { parsePortablePdb } from "./portable-pdb.js";
import type { PortablePdbInfo } from "./portable-pdb-types.js";

export interface PeEmbeddedPortablePdbInfo {
  signature: string;
  uncompressedSize: number;
  compressedSize: number;
  portablePdb?: PortablePdbInfo;
}

// .NET PE/COFF addendum: Embedded Portable PDB payload is MPDB + uncompressed
// size + deflate-compressed Portable PDB bytes.
// Source: dotnet/runtime PE-COFF.md, section
// "Embedded Portable PDB Debug Directory Entry (type 17)".
const EMBEDDED_PORTABLE_PDB_FIXED_SIZE = 8;
const EMBEDDED_PORTABLE_PDB_SIGNATURE = 0x4244504d;

const decodeEmbeddedHeader = (
  view: DataView, size: number, addWarning: (message: string) => void
): PeEmbeddedPortablePdbInfo => {
  const signature = view.getUint32(0, true);
  if (signature !== EMBEDDED_PORTABLE_PDB_SIGNATURE) {
    addWarning("Embedded Portable PDB signature is not MPDB.");
  }
  const uncompressedSize = view.getUint32(4, true);
  if (uncompressedSize === 0) {
    addWarning("Embedded Portable PDB uncompressed size is 0; this value is reserved.");
  }
  const info: PeEmbeddedPortablePdbInfo = {
    signature: String.fromCharCode(
      signature & 0xff,
      (signature >>> 8) & 0xff,
      (signature >>> 16) & 0xff,
      (signature >>> 24) & 0xff
    ),
    uncompressedSize,
    compressedSize: size - EMBEDDED_PORTABLE_PDB_FIXED_SIZE
  };
  return info;
};

const decodeEmbeddedMetadata = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, addressOfRawDataRva: number,
  pointerToRawDataOff: number, info: PeEmbeddedPortablePdbInfo,
  addWarning: (message: string) => void
): Promise<void> => {
  try {
    const compressed = {
      size: info.compressedSize,
      readBytes: async (offset: number, size: number) => {
        const view = await readDebugPayload(reader, rvaToOff,
          addressOfRawDataRva, pointerToRawDataOff, EMBEDDED_PORTABLE_PDB_FIXED_SIZE + offset,
          Math.min(size, info.compressedSize - offset));
        return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      }
    };
    const issues: string[] = [];
    const pdb = await parsePortablePdb(await inflateEmbeddedDebugImage(compressed, info.uncompressedSize), issues);
    issues.forEach(addWarning);
    if (pdb) info.portablePdb = pdb;
  } catch (error) {
    addWarning(`Embedded Portable PDB decompression failed: ${(error as Error).message || "invalid or truncated Deflate stream"}.`);
  }
};

export const parseEmbeddedPortablePdbInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeEmbeddedPortablePdbInfo | null> => {
  const dataInfo = getReadableDebugData(
    "Embedded Portable PDB",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < EMBEDDED_PORTABLE_PDB_FIXED_SIZE) {
    addWarning("Embedded Portable PDB debug entry is smaller than the fixed header.");
    return null;
  }
  const view = await readDebugPayload(reader, rvaToOff, addressOfRawDataRva,
    pointerToRawDataOff, 0, EMBEDDED_PORTABLE_PDB_FIXED_SIZE);
  if (view.byteLength < EMBEDDED_PORTABLE_PDB_FIXED_SIZE) {
    addWarning("Embedded Portable PDB debug entry is truncated.");
    return null;
  }
  const info = decodeEmbeddedHeader(view, dataInfo.size, addWarning);
  if (info.signature !== "MPDB" || info.uncompressedSize === 0) return info;
  if (info.uncompressedSize >= 0x80000000) {
    addWarning("Embedded Portable PDB size has the reserved future-format bit set; not decoded.");
    return info;
  }
  await decodeEmbeddedMetadata(reader, rvaToOff, addressOfRawDataRva, pointerToRawDataOff, info, addWarning);
  return info;
};
