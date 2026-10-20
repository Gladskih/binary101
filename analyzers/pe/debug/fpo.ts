"use strict";

import { readDebugPayload } from "./payload-reader.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../../file-range-reader.js";
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

const validateFpoRecord = (view: DataView, offset: number, warnings: Set<string>): void => {
  // FPO_DATA packed bit 13 is reserved; cbProlog and function range are byte counts.
  // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-fpo_data
  if (view.getUint16(offset + FPO_OFF_PACKED, true) & 0x2000) warnings.add("FPO reserved bit is non-zero.");
  const size = view.getUint32(offset + FPO_OFF_PROCEDURE_SIZE, true);
  if ((view.getUint16(offset + FPO_OFF_PACKED, true) & 0xff) > size) {
    warnings.add("FPO prolog is larger than its procedure.");
  }
  if (view.getUint32(offset + FPO_OFF_START, true) + size > 0x100000000) {
    warnings.add("FPO procedure extends beyond the 32-bit RVA space.");
  }
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
  const records: PeFpoRecord[] = [];
  const warnings = new Set<string>();
  const size = Math.floor(dataInfo.size / FPO_RECORD_SIZE) * FPO_RECORD_SIZE;
  for (let offset = 0; offset < size; offset += DEFAULT_FILE_READ_WINDOW_BYTES) {
    const count = Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, size - offset);
    const view = await readDebugPayload(reader, rvaToOff,
      addressOfRawDataRva, pointerToRawDataOff, offset, count);
    for (let position = 0; position + FPO_RECORD_SIZE <= view.byteLength; position += FPO_RECORD_SIZE) {
      records.push(readFpoRecord(view, position));
      validateFpoRecord(view, position, warnings);
    }
    if (view.byteLength < count) {
      addWarning("FPO debug records are truncated while reading.");
      break;
    }
  }
  warnings.forEach(addWarning);
  return { records };
};
