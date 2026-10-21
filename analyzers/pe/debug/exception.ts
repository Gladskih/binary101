"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseExceptionDirectory, createEmptyExceptionDirectory, type PeExceptionDirectory } from "../exception/index.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { createDebugPayloadReader } from "./payload-reader.js";
import { parseAmd64ExceptionTable } from "../exception/amd64/index.js";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../coff/machine.js";
import { getCanonicalPeMachine } from "../machine.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "../exception/amd64/directory.js";

const parseAmd64Copy = async (reader: FileRangeReader, source: FileRangeReader,
  rvaToOff: RvaToOffset, dataSize: number, tableRva: number | undefined) => {
  if (dataSize < AMD64_RUNTIME_FUNCTION_ENTRY_SIZE) return createEmptyExceptionDirectory([
    "Exception directory size is smaller than one RUNTIME_FUNCTION entry (12 bytes)."], "amd64");
  const issues = dataSize % AMD64_RUNTIME_FUNCTION_ENTRY_SIZE === 0 ? [] :
    ["Exception directory size is not a multiple of RUNTIME_FUNCTION entry size (12 bytes)."];
  return parseAmd64ExceptionTable(reader, source, Math.floor(dataSize / AMD64_RUNTIME_FUNCTION_ENTRY_SIZE),
    rvaToOff, issues, tableRva);
};

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
  const location = getReadableDebugData("EXCEPTION", reader.size, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!location) return null;
  const tableRva = exceptionDirectory?.rva || addressOfRawDataRva;
  if (getCanonicalPeMachine(machine) === IMAGE_FILE_MACHINE_AMD64) {
    return parseAmd64Copy(reader, createDebugPayloadReader(reader, rvaToOff,
      addressOfRawDataRva, pointerToRawDataOff, location.size), rvaToOff, dataSize, tableRva || undefined);
  }
  if (!tableRva) {
    addWarning(`EXCEPTION debug payload has no known table RVA; raw-table decoding is not implemented for machine 0x${machine.toString(16)}.`);
    return null;
  }
  return parseExceptionDirectory(
    reader,
    [{ name: "EXCEPTION", rva: tableRva, size: dataSize }],
    mapExceptionCopy(rvaToOff, tableRva, addressOfRawDataRva, pointerToRawDataOff, dataSize),
    machine
  );
};
