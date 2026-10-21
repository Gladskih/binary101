"use strict";

import { readMappedRvaPrefix } from "../../rva-byte-reader.js";
import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";

// Windows SDK winnt.h defines bit 0 of RUNTIME_FUNCTION.UnwindData as
// RUNTIME_FUNCTION_INDIRECT; dumpbin reports these entries as reusing unwind
// metadata from another RUNTIME_FUNCTION row.
// https://mingw.googlesource.com/mingw-w64/+/refs/tags/v11.0.1/mingw-w64-headers/include/winnt.h
const RUNTIME_FUNCTION_INDIRECT = 0x1;

type RuntimeFunctionEntryValidation = {
  issue: string | null;
  unwindInfoRva: number | null;
};

const getMappedRvaIssue = (
  rva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): string | null => {
  // Microsoft x64 exception handling stores RUNTIME_FUNCTION addresses as
  // image-relative offsets. If an RVA cannot map to bytes in this local file,
  // report the bad reference but do not use it as an UNWIND_INFO seed.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
  const fileOffset = rvaToOff(rva);
  if (fileOffset == null) return `RVA ${formatHex(rva)} does not map to file data`;
  if (fileOffset < 0 || fileOffset >= fileSize) {
    return `RVA ${formatHex(rva)} maps outside the file`;
  }
  return null;
};

const isIndirectRuntimeFunction = (unwindDataRva: number): boolean =>
  (unwindDataRva & RUNTIME_FUNCTION_INDIRECT) !== 0;

const getIndirectRuntimeFunctionRva = (unwindDataRva: number): number =>
  (unwindDataRva & ~RUNTIME_FUNCTION_INDIRECT) >>> 0;

const getExceptionDirectoryIssue = (
  rva: number,
  exceptionDirectoryRva: number,
  exceptionDirectorySize: number
): string | null => {
  const endRva = rva + AMD64_RUNTIME_FUNCTION_ENTRY_SIZE;
  if (rva < exceptionDirectoryRva || endRva > exceptionDirectoryRva + exceptionDirectorySize) {
    return "points outside the RUNTIME_FUNCTION table";
  }
  if ((rva - exceptionDirectoryRva) % AMD64_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    return "does not point to the start of a RUNTIME_FUNCTION entry";
  }
  return null;
};

const readIndirectUnwindInfoRva = async (
  reader: FileRangeReader,
  indirectRuntimeFunctionRva: number,
  rvaToOff: RvaToOffset,
  exceptionDirectoryRva: number,
  source?: FileRangeReader
): Promise<number | null> => {
  const view = source ? await source.read(indirectRuntimeFunctionRva - exceptionDirectoryRva + 8,
    Uint32Array.BYTES_PER_ELEMENT) : await readMappedRvaPrefix(reader, indirectRuntimeFunctionRva + 8,
    Uint32Array.BYTES_PER_ELEMENT, rvaToOff);
  return view.byteLength === Uint32Array.BYTES_PER_ELEMENT
    ? view.getUint32(0, true) >>> 0
    : null;
};

const resolveDirectUnwindInfoRva = (
  reader: FileRangeReader, unwindDataRva: number, exceptionDirectoryRva: number | undefined,
  exceptionDirectorySize: number, rvaToOff: RvaToOffset
): RuntimeFunctionEntryValidation => {
  if (exceptionDirectoryRva !== undefined && unwindDataRva >= exceptionDirectoryRva &&
      unwindDataRva < exceptionDirectoryRva + exceptionDirectorySize) {
    return { issue: "UnwindData points back into the RUNTIME_FUNCTION table", unwindInfoRva: null };
  }
  const unwindIssue = getMappedRvaIssue(unwindDataRva, rvaToOff, reader.size);
  return { issue: unwindIssue ? `UnwindData ${unwindIssue}` : null,
    unwindInfoRva: unwindIssue ? null : unwindDataRva };
};

const resolveUnwindInfoRva = async (
  reader: FileRangeReader,
  unwindDataRva: number,
  exceptionDirectoryRva: number | undefined,
  exceptionDirectorySize: number,
  rvaToOff: RvaToOffset,
  visitedIndirectRvas = new Set<number>(),
  source?: FileRangeReader
): Promise<RuntimeFunctionEntryValidation> => {
  if (!unwindDataRva) return { issue: "UnwindData is zero", unwindInfoRva: null };
  if (!isIndirectRuntimeFunction(unwindDataRva)) {
    return resolveDirectUnwindInfoRva(reader, unwindDataRva, exceptionDirectoryRva,
      exceptionDirectorySize, rvaToOff);
  }
  if (exceptionDirectoryRva === undefined) {
    return { issue: "Indirect UnwindData cannot be validated because the table origin is unknown", unwindInfoRva: null };
  }
  const indirectRuntimeFunctionRva = getIndirectRuntimeFunctionRva(unwindDataRva);
  if (visitedIndirectRvas.has(indirectRuntimeFunctionRva)) {
    return { issue: "Indirect UnwindData forms a cycle", unwindInfoRva: null };
  }
  visitedIndirectRvas.add(indirectRuntimeFunctionRva);
  const indirectIssue = getExceptionDirectoryIssue(
    indirectRuntimeFunctionRva,
    exceptionDirectoryRva,
    exceptionDirectorySize
  );
  if (indirectIssue) return { issue: `Indirect UnwindData ${indirectIssue}`, unwindInfoRva: null };
  const unwindInfoRva = await readIndirectUnwindInfoRva(
    reader,
    indirectRuntimeFunctionRva,
    rvaToOff,
    exceptionDirectoryRva,
    source
  );
  if (unwindInfoRva == null) {
    return { issue: "Indirect UnwindData target could not be read", unwindInfoRva: null };
  }
  return resolveUnwindInfoRva(
    reader,
    unwindInfoRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    rvaToOff,
    visitedIndirectRvas,
    source
  );
};

export const validateAmd64RuntimeFunction = async (
  reader: FileRangeReader,
  beginRva: number,
  endRva: number,
  unwindDataRva: number,
  exceptionDirectoryRva: number | undefined,
  exceptionDirectorySize: number,
  rvaToOff: RvaToOffset,
  source?: FileRangeReader
): Promise<RuntimeFunctionEntryValidation> => {
  // Microsoft documents .pdata as sorted RUNTIME_FUNCTION records with
  // image-relative function start, function end, and unwind data. Chained
  // RUNTIME_FUNCTION records are trailing UNWIND_INFO payload; indirect
  // RUNTIME_FUNCTION rows use the Windows header low-bit marker instead.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  if (beginRva >= endRva) {
    return { issue: "BeginAddress is greater than or equal to EndAddress", unwindInfoRva: null };
  }
  const beginIssue = getMappedRvaIssue(beginRva, rvaToOff, reader.size);
  if (beginIssue) return { issue: `BeginAddress ${beginIssue}`, unwindInfoRva: null };
  const endIssue = getMappedRvaIssue(endRva - 1, rvaToOff, reader.size);
  if (endIssue) return { issue: `EndAddress ${endIssue}`, unwindInfoRva: null };
  // Leaf functions without unwind state are omitted from .pdata; once a
  // RUNTIME_FUNCTION record exists, the unwind data is required.
  return resolveUnwindInfoRva(
    reader,
    unwindDataRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    rvaToOff,
    new Set<number>(),
    source
  );
};

const formatHex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

