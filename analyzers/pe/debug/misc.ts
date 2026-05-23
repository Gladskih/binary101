"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeMiscDebugInfo {
  dataType: number;
  length: number;
  unicode: boolean;
  text: string;
}

const IMAGE_DEBUG_MISC_FIXED_SIZE = 12;
const IMAGE_DEBUG_MISC_OFF_DATA_TYPE = 0;
const IMAGE_DEBUG_MISC_OFF_LENGTH = 4;
const IMAGE_DEBUG_MISC_OFF_UNICODE = 8;
const IMAGE_DEBUG_MISC_OFF_DATA = 12;

const decodeMiscText = (payload: Uint8Array, unicode: boolean): string => {
  const zeroWidth = unicode ? 2 : 1;
  let textEnd = payload.length;
  for (let index = 0; index <= payload.length - zeroWidth; index += zeroWidth) {
    if (payload[index] === 0 && (!unicode || payload[index + 1] === 0)) {
      textEnd = index;
      break;
    }
  }
  return new TextDecoder(unicode ? "utf-16le" : "windows-1252").decode(payload.slice(0, textEnd));
};

export const parseMiscDebugInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeMiscDebugInfo | null> => {
  const dataInfo = getReadableDebugData(
    "MISC",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < IMAGE_DEBUG_MISC_FIXED_SIZE) {
    addWarning("MISC debug entry is smaller than IMAGE_DEBUG_MISC.");
    return null;
  }
  const payload = await reader.readBytes(dataInfo.offset, dataInfo.size);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const length = view.getUint32(IMAGE_DEBUG_MISC_OFF_LENGTH, true);
  if (length > dataInfo.size) addWarning("MISC debug entry length exceeds SizeOfData.");
  return {
    dataType: view.getUint32(IMAGE_DEBUG_MISC_OFF_DATA_TYPE, true),
    length,
    unicode: view.getUint8(IMAGE_DEBUG_MISC_OFF_UNICODE) !== 0,
    text: decodeMiscText(
      payload.slice(IMAGE_DEBUG_MISC_OFF_DATA, Math.min(length || dataInfo.size, dataInfo.size)),
      view.getUint8(IMAGE_DEBUG_MISC_OFF_UNICODE) !== 0
    )
  };
};
