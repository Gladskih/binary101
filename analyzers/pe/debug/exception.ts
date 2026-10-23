"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseExceptionDirectory, createEmptyExceptionDirectory, type PeExceptionDirectory } from "../exception/index.js";
import type { PeDataDirectory, PeWindowsOptionalHeader, RvaToOffset } from "../types.js";
import { getNtRiscExceptionFormat } from "../exception/nt-risc-directory.js";
import { parseNtRiscExceptionTable } from "../exception/nt-risc.js";
import { isCeExceptionMachine } from "../exception/ce-directory.js";
import { parseCeExceptionTable } from "../exception/ce.js";
import { parseIa64ExceptionTable } from "../exception/ia64.js";
import { getReadableDebugData } from "./data.js";
import { createDebugPayloadReader } from "./payload-reader.js";
import { parseAmd64ExceptionTable } from "../exception/amd64/index.js";
import { parseArm64ExceptionTable } from "../exception/arm64.js";
import { parseArmntExceptionTable } from "../exception/armnt.js";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X, IMAGE_FILE_MACHINE_ARMNT,
  IMAGE_FILE_MACHINE_IA64 } from "../../coff/machine.js";
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

const parseMachineCopy = async (reader: FileRangeReader, source: FileRangeReader,
  rvaToOff: RvaToOffset, dataSize: number, machine: number, tableRva: number | undefined,
  header: PeWindowsOptionalHeader | undefined): Promise<PeExceptionDirectory | null> => {
  if (machine === IMAGE_FILE_MACHINE_AMD64) return parseAmd64Copy(reader, source, rvaToOff, dataSize, tableRva);
  if ([IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X].includes(machine)) {
    return parseArm64ExceptionTable(reader, source, dataSize, rvaToOff, tableRva);
  }
  if (machine === IMAGE_FILE_MACHINE_ARMNT) return parseArmntExceptionTable(reader, source, dataSize, rvaToOff);
  if (machine === IMAGE_FILE_MACHINE_IA64) return parseIa64ExceptionTable(reader, source, dataSize, rvaToOff);
  if (isCeExceptionMachine(machine, header)) {
    return parseCeExceptionTable(reader, source, dataSize, rvaToOff, header?.ImageBase, machine);
  }
  const ntRiscFormat = getNtRiscExceptionFormat(machine, header);
  return ntRiscFormat
    ? parseNtRiscExceptionTable(reader, source, dataSize, rvaToOff, ntRiscFormat, header?.ImageBase) : null;
};

// Microsoft PE format, "Debug Type": IMAGE_DEBUG_TYPE_EXCEPTION is a copy of
// the .pdata section, so it can be decoded with the same machine-specific parser.
// Entries retain image addresses (VAs or RVAs according to the machine ABI),
// including indirect references. The copy's storage RVA does not replace its origin.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
export const createExceptionDebugParser = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, machine: number, header?: PeWindowsOptionalHeader
) => async (
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void,
  exceptionDirectory?: PeDataDirectory
): Promise<PeExceptionDirectory | null> => {
  if (dataSize <= 0) return null;
  const location = getReadableDebugData("EXCEPTION", reader.size, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!location) return null;
  const tableRva = exceptionDirectory?.rva || addressOfRawDataRva;
  const source = createDebugPayloadReader(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, location.size);
  const parsed = await parseMachineCopy(reader, source, rvaToOff, dataSize,
    getCanonicalPeMachine(machine), tableRva || undefined, header);
  if (parsed) return parsed;
  if (!tableRva) {
    addWarning(`EXCEPTION debug payload has no known table RVA; raw-table decoding is not implemented for machine 0x${machine.toString(16)}.`);
    return null;
  }
  return parseExceptionDirectory(
    reader,
    [{ name: "EXCEPTION", rva: tableRva, size: dataSize }],
    rvaToOff,
    machine
  );
};

export const parseExceptionDebugInfo = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, addressOfRawDataRva: number,
  pointerToRawDataOff: number, dataSize: number, machine: number,
  addWarning: (message: string) => void, exceptionDirectory?: PeDataDirectory
): Promise<PeExceptionDirectory | null> => createExceptionDebugParser(reader, rvaToOff, machine)(
  addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning, exceptionDirectory);
