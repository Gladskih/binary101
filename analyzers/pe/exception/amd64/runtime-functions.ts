import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import { createRvaRangeReader } from "../../rva-range-reader.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";
import { readAmd64RuntimeFunctionTable, type Amd64RuntimeFunctionTable } from "./runtime-function-table.js";

export const readAmd64RuntimeFunctions = (
  reader: FileRangeReader, directoryRva: number, entryCount: number,
  rvaToOff: RvaToOffset, issues: string[]
): Promise<Amd64RuntimeFunctionTable> => readAmd64RuntimeFunctionTable(reader,
  createRvaRangeReader(reader, rvaToOff, directoryRva, entryCount * AMD64_RUNTIME_FUNCTION_ENTRY_SIZE),
  entryCount, rvaToOff, issues, directoryRva);
