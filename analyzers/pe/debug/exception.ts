"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseExceptionDirectory, type PeExceptionDirectory } from "../exception/index.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

const mapExceptionCopy = (rvaToOff: RvaToOffset, tableRva: number,
  sourceRva: number, sourceOffset: number, size: number): RvaToOffset => rva => {
  if (rva < tableRva || rva >= tableRva + size) return rvaToOff(rva);
  return sourceOffset ? sourceOffset + rva - tableRva : rvaToOff(sourceRva + rva - tableRva);
};

// Microsoft PE format, "Debug Type": IMAGE_DEBUG_TYPE_EXCEPTION is a copy of
// the .pdata section, so it can be decoded with the same machine-specific parser.
// Entries retain image RVAs, including indirect references into the original
// table. The debug copy's storage RVA is not a replacement for that origin.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
export const parseExceptionDebugInfo = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  machine: number,
  addWarning: (message: string) => void,
  exceptionDirectory?: PeDataDirectory
): Promise<PeExceptionDirectory | null> => {
  if (dataSize <= 0) return null;
  const tableRva = exceptionDirectory?.rva || addressOfRawDataRva;
  if (!tableRva) {
    addWarning("EXCEPTION debug payload has no raw-data RVA; .pdata copy was not decoded.");
    return null;
  }
  if (!getReadableDebugData("EXCEPTION", reader.size, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning)) return null;
  return parseExceptionDirectory(
    reader,
    [{ name: "EXCEPTION", rva: tableRva, size: dataSize }],
    mapExceptionCopy(rvaToOff, tableRva, addressOfRawDataRva, pointerToRawDataOff, dataSize),
    machine
  );
};
