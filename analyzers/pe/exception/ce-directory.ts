import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, PeWindowsOptionalHeader, RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { parseCeExceptionTable } from "./ce.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

export const isCeExceptionMachine = (machine: number, header?: PeWindowsOptionalHeader): boolean =>
  // ARM/Thumb, SH3/SH3DSP/SH4, and PowerPC Windows CE use compressed PDATA.
  // PowerPC NT is distinguished by the subsystem, not by payload length.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
  [0x1c0, 0x1c2, 0x1a2, 0x1a3, 0x1a6].includes(machine) ||
    ([0x1f0, 0x1f1].includes(machine) && header?.Subsystem === 9);

const parseDirectory = async (reader: FileRangeReader, directory: PeDataDirectory,
  rvaToOff: RvaToOffset, machine: number, header: PeWindowsOptionalHeader | undefined
): Promise<PeExceptionDirectory | null> => {
  if (directory.rva === 0 && directory.size === 0) return null;
  if (directory.rva === 0) return createEmptyExceptionDirectory([
    "Exception directory has a non-zero size but RVA is 0."], "ce");
  const offset = rvaToOff(directory.rva);
  if (offset == null) return createEmptyExceptionDirectory([
    "Exception directory RVA could not be mapped to a file offset."], "ce");
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) return createEmptyExceptionDirectory([
    "Exception directory location is outside the file."], "ce");
  return parseCeExceptionTable(reader,
    createRvaRangeReader(reader, rvaToOff, directory.rva, directory.size), directory.size,
    rvaToOff, header?.ImageBase, machine);
};

export const parseCeExceptionDirectory = async (reader: FileRangeReader, dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset, machine: number, header?: PeWindowsOptionalHeader
): Promise<PeExceptionDirectory | null> => {
  const directory = dataDirs.find(entry => entry.name === "EXCEPTION");
  if (!isCeExceptionMachine(machine, header) || !directory) return null;
  return parseDirectory(reader, directory, rvaToOff, machine, header);
};
