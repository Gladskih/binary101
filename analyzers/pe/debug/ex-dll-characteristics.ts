"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeExDllCharacteristicsInfo {
  value: number;
}

const EX_DLL_CHARACTERISTICS_SIZE = 4;

// Microsoft PE/COFF: EX_DLLCHARACTERISTICS raw data points to extended DLL
// characteristics bits.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
export const parseExDllCharacteristicsInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeExDllCharacteristicsInfo | null> => {
  const dataInfo = getReadableDebugData(
    "EX_DLLCHARACTERISTICS",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < EX_DLL_CHARACTERISTICS_SIZE) {
    addWarning("EX_DLLCHARACTERISTICS debug entry is smaller than the 4-byte bit field.");
    return null;
  }
  if (dataInfo.size > EX_DLL_CHARACTERISTICS_SIZE) {
    addWarning("EX_DLLCHARACTERISTICS debug entry has trailing bytes after the 4-byte bit field.");
  }
  const view = await reader.read(dataInfo.offset, EX_DLL_CHARACTERISTICS_SIZE);
  if (view.byteLength < EX_DLL_CHARACTERISTICS_SIZE) {
    addWarning("EX_DLLCHARACTERISTICS debug entry is truncated.");
    return null;
  }
  return { value: view.getUint32(0, true) };
};
