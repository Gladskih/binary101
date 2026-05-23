"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeFpoRecord {
  startOffset: number;
  procedureSize: number;
  localDwordCount: number;
  parameterDwordCount: number;
  prologByteCount: number;
  savedRegisterCount: number;
  hasStructuredExceptionHandling: boolean;
  usesBasePointer: boolean;
  frameType: number;
}

export interface PeFpoInfo {
  records: PeFpoRecord[];
}

// Microsoft PE/COFF defines FPO_DATA as five scalar fields packed into 16 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const FPO_RECORD_SIZE = 16;
const FPO_OFF_START = 0;
const FPO_OFF_PROCEDURE_SIZE = 4;
const FPO_OFF_LOCAL_DWORDS = 8;
const FPO_OFF_PARAMETER_DWORDS = 12;
const FPO_OFF_PACKED = 14;

const readFpoRecord = (view: DataView, offset: number): PeFpoRecord => {
  const packed = view.getUint16(offset + FPO_OFF_PACKED, true);
  return {
    startOffset: view.getUint32(offset + FPO_OFF_START, true),
    procedureSize: view.getUint32(offset + FPO_OFF_PROCEDURE_SIZE, true),
    localDwordCount: view.getUint32(offset + FPO_OFF_LOCAL_DWORDS, true),
    parameterDwordCount: view.getUint16(offset + FPO_OFF_PARAMETER_DWORDS, true),
    prologByteCount: packed & 0xff,
    savedRegisterCount: (packed >>> 8) & 0x7,
    hasStructuredExceptionHandling: ((packed >>> 11) & 0x1) !== 0,
    usesBasePointer: ((packed >>> 12) & 0x1) !== 0,
    frameType: (packed >>> 14) & 0x3
  };
};

export const parseFpoInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeFpoInfo | null> => {
  const dataInfo = getReadableDebugData(
    "FPO",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < FPO_RECORD_SIZE) {
    addWarning("FPO debug entry is smaller than one FPO_DATA record.");
    return null;
  }
  if (dataInfo.size % FPO_RECORD_SIZE !== 0) {
    addWarning("FPO debug entry has trailing bytes after whole FPO_DATA records.");
  }
  const payload = await reader.readBytes(
    dataInfo.offset,
    Math.floor(dataInfo.size / FPO_RECORD_SIZE) * FPO_RECORD_SIZE
  );
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const records = Array.from({ length: payload.byteLength / FPO_RECORD_SIZE }, (_, index) =>
    readFpoRecord(view, index * FPO_RECORD_SIZE)
  );
  return { records };
};
