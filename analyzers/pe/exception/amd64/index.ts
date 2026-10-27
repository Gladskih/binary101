"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../../types.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "../types.js";
import { resolveAmd64ExceptionDirectory } from "./directory.js";
import { readAmd64RuntimeFunctionTable } from "./runtime-function-table.js";
import { scanAmd64UnwindInfos } from "./unwind-info.js";
import { createRvaRangeReader } from "../../rva-range-reader.js";
import { resolveAmd64HandlerOwners } from "./handler-owners.js";

export const parseAmd64ExceptionDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> => {
  const directory = resolveAmd64ExceptionDirectory(reader.size, dataDirs, rvaToOff);
  if (directory.kind === "absent") return null;
  if (directory.kind === "invalid") return directory.result;
  return parseAmd64ExceptionTable(reader, createRvaRangeReader(reader, rvaToOff,
    directory.directory.rva, directory.directory.size), directory.entryCount,
    rvaToOff, directory.issues, directory.directory.rva);
};

export const parseAmd64ExceptionTable = async (
  reader: FileRangeReader, source: FileRangeReader, entryCount: number,
  rvaToOff: RvaToOffset, issues: string[], directoryRva?: number
): Promise<PeExceptionDirectory> => {
  const runtimeFunctions = await readAmd64RuntimeFunctionTable(reader, source, entryCount,
    rvaToOff, issues, directoryRva);
  if (runtimeFunctions.functionCount === 0) {
    issues.push("Exception directory does not contain a complete RUNTIME_FUNCTION entry.");
    return createEmptyExceptionDirectory(issues, "amd64");
  }
  const unwindInfo = await scanAmd64UnwindInfos(
    reader,
    rvaToOff,
    runtimeFunctions.unwindRvas,
    issues
  );
  const handlerOwners = resolveAmd64HandlerOwners(runtimeFunctions.functionsByUnwindRva,
    unwindInfo.chainedUnwindRvas ?? new Map<number, number>(), issues);
  return {
    functionCount: runtimeFunctions.functionCount,
    beginRvas: runtimeFunctions.beginRvas,
    rangeLengths: runtimeFunctions.rangeLengths,
    handlerRvas: unwindInfo.handlerRvas,
    ...(unwindInfo.languageHandlers ? { languageHandlers: unwindInfo.languageHandlers.map(handler => ({
      ...handler, functionRanges: handlerOwners.get(handler.unwindInfoRva) ?? []
    })) } : {}),
    uniqueUnwindInfoCount: unwindInfo.uniqueUnwindInfoCount,
    unwindInfoVersion1Count: unwindInfo.unwindInfoVersion1Count,
    unwindInfoVersion2Count: unwindInfo.unwindInfoVersion2Count,
    ...(unwindInfo.version3 ? { unwindInfoV3: unwindInfo.version3 } : {}),
    ...(unwindInfo.version12 ? { unwindInfoV12: unwindInfo.version12 } : {}),
    epilogUnwindInfoCount: unwindInfo.epilogUnwindInfoCount,
    epilogScopeCount: unwindInfo.epilogScopeCount,
    handlerUnwindInfoCount: unwindInfo.handlerUnwindInfoCount,
    chainedUnwindInfoCount: unwindInfo.chainedUnwindInfoCount,
    invalidEntryCount: runtimeFunctions.invalidEntryCount,
    issues,
    format: "amd64"
  };
};
