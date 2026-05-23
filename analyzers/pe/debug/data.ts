"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";

export type PeDebugDataLocation = {
  offset: number;
  size: number;
};

export const getReadableDebugData = (
  label: string,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): PeDebugDataLocation | null => {
  const offset = pointerToRawDataOff || (
    addressOfRawDataRva ? rvaToOff(addressOfRawDataRva) : null
  );
  if (offset == null || offset < 0) {
    addWarning(
      pointerToRawDataOff || addressOfRawDataRva
        ? `${label} debug entry does not map to file data.`
        : `${label} debug entry has no PointerToRawData/AddressOfRawData.`
    );
    return null;
  }
  if (offset >= fileSize) {
    addWarning(`${label} debug entry starts past end of file.`);
    return null;
  }
  const size = Math.min(dataSize, Math.max(0, fileSize - offset));
  if (size < dataSize) addWarning(`${label} debug entry is shorter than its declared SizeOfData.`);
  return { offset, size };
};

export const readDebugBytes = async (
  reader: FileRangeReader,
  dataInfo: PeDebugDataLocation,
  maxBytes: number
): Promise<number[]> => [...await reader.readBytes(dataInfo.offset, Math.min(dataInfo.size, maxBytes))];
