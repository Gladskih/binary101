"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PePdbChecksumInfo {
  algorithmName: string;
  checksumBytes: number[];
}

const textDecoder = new TextDecoder();

// .NET PE/COFF addendum: PDB checksum payload is a NUL-terminated algorithm
// name followed by checksum bytes.
// Source: dotnet/runtime PE-COFF.md,
// section "PDB Checksum Debug Directory Entry (type 19)".
export const parsePdbChecksumInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PePdbChecksumInfo | null> => {
  const dataInfo = getReadableDebugData(
    "PDB checksum",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  const payload = await reader.readBytes(dataInfo.offset, dataInfo.size);
  const zeroIndex = payload.indexOf(0);
  if (zeroIndex === -1) {
    addWarning("PDB checksum algorithm name is not NUL-terminated within SizeOfData.");
    return null;
  }
  if (zeroIndex === 0) addWarning("PDB checksum algorithm name is empty.");
  return {
    algorithmName: textDecoder.decode(payload.slice(0, zeroIndex)),
    checksumBytes: [...payload.slice(zeroIndex + 1)]
  };
};
