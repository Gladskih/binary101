"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseExceptionDirectory, type PeExceptionDirectory } from "../exception/index.js";
import type { RvaToOffset } from "../types.js";

// Microsoft PE format, "Debug Type": IMAGE_DEBUG_TYPE_EXCEPTION is a copy of
// the .pdata section, so it can be decoded with the same machine-specific parser.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
export const parseExceptionDebugInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  machine: number,
  addWarning: (message: string) => void
): Promise<PeExceptionDirectory | null> => {
  if (dataSize <= 0) return null;
  if (!addressOfRawDataRva) {
    addWarning("EXCEPTION debug payload has no raw-data RVA; .pdata copy was not decoded.");
    return null;
  }
  const mappedPayloadOffset = rvaToOff(addressOfRawDataRva);
  const payloadOffset = pointerToRawDataOff || mappedPayloadOffset;
  if (payloadOffset == null || payloadOffset < 0 || payloadOffset >= fileSize) {
    addWarning("EXCEPTION debug payload does not map to a readable file offset.");
    return null;
  }
  const debugPayloadRvaToOff = (rva: number): number | null => {
    if (rva >= addressOfRawDataRva && rva < addressOfRawDataRva + dataSize) {
      return payloadOffset + rva - addressOfRawDataRva;
    }
    return rvaToOff(rva);
  };
  return parseExceptionDirectory(
    reader,
    [{ name: "EXCEPTION", rva: addressOfRawDataRva, size: dataSize }],
    debugPayloadRvaToOff,
    machine
  );
};
