"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeReproInfo {
  hashLength: number | null;
  hashBytes: number[];
}

const REPRO_HASH_LENGTH_SIZE = 4;

export const parseReproInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeReproInfo | null> => {
  if (dataSize === 0) return { hashLength: null, hashBytes: [] };
  const dataInfo = getReadableDebugData(
    "REPRO",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < REPRO_HASH_LENGTH_SIZE) {
    addWarning("REPRO debug entry is smaller than the hash-length field.");
    return { hashLength: null, hashBytes: [] };
  }
  const header = await reader.read(dataInfo.offset, REPRO_HASH_LENGTH_SIZE);
  if (header.byteLength < REPRO_HASH_LENGTH_SIZE) {
    addWarning("REPRO debug entry is truncated before the hash-length field.");
    return { hashLength: null, hashBytes: [] };
  }
  const hashLength = header.getUint32(0, true);
  const availableHashBytes = Math.max(0, dataInfo.size - REPRO_HASH_LENGTH_SIZE);
  if (hashLength > availableHashBytes) addWarning("REPRO hash is shorter than its declared length.");
  if (hashLength < availableHashBytes) addWarning("REPRO debug entry has trailing bytes after the hash.");
  return {
    hashLength,
    hashBytes: [...await reader.readBytes(
      dataInfo.offset + REPRO_HASH_LENGTH_SIZE,
      Math.min(hashLength, availableHashBytes)
    )]
  };
};
