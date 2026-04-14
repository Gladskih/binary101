"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";

export interface PeVcFeatureInfo {
  preVc11: number;
  cAndCpp: number;
  gs: number;
  sdl: number;
  guardN: number;
}

// Upstream PE parsers model IMAGE_DEBUG_TYPE_VC_FEATURE as five DWORD counters:
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const VC_FEATURE_FIXED_SIZE = 20;
const VC_FEATURE_OFF_PRE_VC11 = 0;
const VC_FEATURE_OFF_C_AND_CPP = 4;
const VC_FEATURE_OFF_GS = 8;
const VC_FEATURE_OFF_SDL = 12;
const VC_FEATURE_OFF_GUARDN = 16;

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
        ? "VC_FEATURE debug entry does not map to file data."
        : "VC_FEATURE debug entry has no PointerToRawData/AddressOfRawData."
    );
    return null;
  }
  if (offset >= fileSize) {
    addWarning("VC_FEATURE debug entry starts past end of file.");
    return null;
  }
  const size = Math.min(dataSize, Math.max(0, fileSize - offset));
  if (size < dataSize) {
    addWarning("VC_FEATURE debug entry is shorter than its declared SizeOfData.");
  }
  return { offset, size };
};

export const parseVcFeatureInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeVcFeatureInfo | null> => {
  const dataInfo = getReadableDebugData(
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < VC_FEATURE_FIXED_SIZE) {
    addWarning("VC_FEATURE debug entry is smaller than the fixed five-counter layout.");
    return null;
  }
  const view = await reader.read(dataInfo.offset, VC_FEATURE_FIXED_SIZE);
  if (view.byteLength < VC_FEATURE_FIXED_SIZE) {
    addWarning("VC_FEATURE debug entry is truncated.");
    return null;
  }
  return {
    preVc11: view.getUint32(VC_FEATURE_OFF_PRE_VC11, true),
    cAndCpp: view.getUint32(VC_FEATURE_OFF_C_AND_CPP, true),
    gs: view.getUint32(VC_FEATURE_OFF_GS, true),
    sdl: view.getUint32(VC_FEATURE_OFF_SDL, true),
    guardN: view.getUint32(VC_FEATURE_OFF_GUARDN, true)
  };
};
