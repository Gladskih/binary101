"use strict";

import { readDebugPayloadBytes } from "./payload-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeRawDebugPayload {
  previewBytes: number[];
}

const RAW_PAYLOAD_PREVIEW_SIZE = 32;

export const parseRawDebugPayload = async (
  label: string,
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeRawDebugPayload | null> => {
  const dataInfo = getReadableDebugData(
    label,
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  return dataInfo ? { previewBytes: [...await readDebugPayloadBytes(reader, rvaToOff, addressOfRawDataRva,
    pointerToRawDataOff, 0, Math.min(dataInfo.size, RAW_PAYLOAD_PREVIEW_SIZE))] } : null;
};
