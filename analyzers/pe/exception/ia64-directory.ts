import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { parseIa64ExceptionTable } from "./ia64.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

export const parseIa64ExceptionDirectory = async (reader: FileRangeReader,
  dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> => {
  const directory = dataDirs.find(entry => entry.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  if (directory.rva === 0) return createEmptyExceptionDirectory([
    "Exception directory has a non-zero size but RVA is 0."], "ia64");
  const offset = rvaToOff(directory.rva);
  if (offset == null) return createEmptyExceptionDirectory([
    "Exception directory RVA could not be mapped to a file offset."], "ia64");
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) return createEmptyExceptionDirectory([
    "Exception directory location is outside the file."], "ia64");
  return parseIa64ExceptionTable(reader,
    createRvaRangeReader(reader, rvaToOff, directory.rva, directory.size), directory.size, rvaToOff);
};
