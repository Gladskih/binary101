"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeEmbeddedPortablePdbInfo {
  signature: string;
  uncompressedSize: number;
  compressedSize: number;
}

// .NET PE/COFF addendum: Embedded Portable PDB payload is MPDB + uncompressed
// size + deflate-compressed Portable PDB bytes.
// Source: dotnet/runtime PE-COFF.md, section
// "Embedded Portable PDB Debug Directory Entry (type 17)".
const EMBEDDED_PORTABLE_PDB_FIXED_SIZE = 8;
const EMBEDDED_PORTABLE_PDB_SIGNATURE = 0x4244504d;

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
  const view = await reader.read(dataInfo.offset, EMBEDDED_PORTABLE_PDB_FIXED_SIZE);
  if (view.byteLength < EMBEDDED_PORTABLE_PDB_FIXED_SIZE) {
    addWarning("Embedded Portable PDB debug entry is truncated.");
    return null;
  }
  const signature = view.getUint32(0, true);
  if (signature !== EMBEDDED_PORTABLE_PDB_SIGNATURE) {
    addWarning("Embedded Portable PDB signature is not MPDB.");
  }
  const uncompressedSize = view.getUint32(4, true);
  if (uncompressedSize === 0) {
    addWarning("Embedded Portable PDB uncompressed size is 0; this value is reserved.");
  }
  return {
    signature: String.fromCharCode(
      signature & 0xff,
      (signature >>> 8) & 0xff,
      (signature >>> 16) & 0xff,
      (signature >>> 24) & 0xff
    ),
    uncompressedSize,
    compressedSize: dataInfo.size - EMBEDDED_PORTABLE_PDB_FIXED_SIZE
  };
};
