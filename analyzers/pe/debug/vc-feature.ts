"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeVcFeatureInfo {
  preVc11: number;
  cAndCpp: number;
  gs: number;
  sdl: number;
  guardN?: number;
}

// Upstream PE parsers model IMAGE_DEBUG_TYPE_VC_FEATURE as five DWORD counters:
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const VC_FEATURE_FIXED_SIZE = 20;
const VC_FEATURE_LEGACY_SIZE = 16;
const VC_FEATURE_OFF_PRE_VC11 = 0;
const VC_FEATURE_OFF_C_AND_CPP = 4;
const VC_FEATURE_OFF_GS = 8;
const VC_FEATURE_OFF_SDL = 12;
const VC_FEATURE_OFF_GUARDN = 16;

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
    "VC_FEATURE",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < VC_FEATURE_LEGACY_SIZE) {
    addWarning("VC_FEATURE debug entry is smaller than the known four-counter layout.");
    return null;
  }
  if (dataInfo.size < VC_FEATURE_FIXED_SIZE) {
    addWarning("VC_FEATURE debug entry uses a legacy four-counter layout without guardN.");
  }
  const view = await reader.read(dataInfo.offset, Math.min(dataInfo.size, VC_FEATURE_FIXED_SIZE));
  if (view.byteLength < VC_FEATURE_LEGACY_SIZE) {
    addWarning("VC_FEATURE debug entry is truncated.");
    return null;
  }
  return {
    preVc11: view.getUint32(VC_FEATURE_OFF_PRE_VC11, true),
    cAndCpp: view.getUint32(VC_FEATURE_OFF_C_AND_CPP, true),
    gs: view.getUint32(VC_FEATURE_OFF_GS, true),
    sdl: view.getUint32(VC_FEATURE_OFF_SDL, true),
    ...(view.byteLength >= VC_FEATURE_FIXED_SIZE
      ? { guardN: view.getUint32(VC_FEATURE_OFF_GUARDN, true) }
      : {})
  };
};
