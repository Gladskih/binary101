import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, PeWindowsOptionalHeader, RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { parseNtRiscExceptionTable, type NtRiscExceptionFormat } from "./nt-risc.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

export const getNtRiscExceptionFormat = (machine: number,
  header?: PeWindowsOptionalHeader): NtRiscExceptionFormat | undefined => {
  // Windows SDK machine IDs: R3000, R4000, R10000, Alpha, Alpha64, PowerPC/FP.
  // PowerPC Windows CE (subsystem 9) uses the separate compressed CE format.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
  if (machine === 0x284) return "nt-risc64";
  if ([0x162, 0x166, 0x168, 0x184].includes(machine)) return "nt-risc32";
  if ([0x1f0, 0x1f1].includes(machine) && header && header.Subsystem !== 9) return "nt-risc32";
  return undefined;
};

export const parseNtRiscExceptionDirectory = async (
  reader: FileRangeReader, dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset,
  machine: number, header?: PeWindowsOptionalHeader
): Promise<PeExceptionDirectory | null> => {
  const format = getNtRiscExceptionFormat(machine, header);
  const directory = dataDirs.find(entry => entry.name === "EXCEPTION");
  if (!format || !directory) return null;
  return parseDirectory(reader, directory, rvaToOff, format, machine, header);
};

const parseDirectory = async (reader: FileRangeReader, directory: PeDataDirectory,
  rvaToOff: RvaToOffset, format: NtRiscExceptionFormat, machine: number,
  header: PeWindowsOptionalHeader | undefined): Promise<PeExceptionDirectory | null> => {
  if (directory.rva === 0 && directory.size === 0) return null;
  if (directory.rva === 0) return createEmptyExceptionDirectory([
    "Exception directory has a non-zero size but RVA is 0."], format);
  const offset = rvaToOff(directory.rva);
  if (offset == null) return createEmptyExceptionDirectory([
    "Exception directory RVA could not be mapped to a file offset."], format);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) return createEmptyExceptionDirectory([
    "Exception directory location is outside the file."], format);
  return parseNtRiscExceptionTable(reader,
    createRvaRangeReader(reader, rvaToOff, directory.rva, directory.size), directory.size,
    rvaToOff, format, header?.ImageBase, machine);
};
