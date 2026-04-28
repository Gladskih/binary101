"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../../types.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "../types.js";
import { resolveAmd64ExceptionDirectory } from "./directory.js";
import { readAmd64RuntimeFunctions } from "./runtime-functions.js";
import { scanAmd64UnwindInfos } from "./unwind-info.js";

export const parseAmd64ExceptionDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeExceptionDirectory | null> => {
  const directory = resolveAmd64ExceptionDirectory(reader.size, dataDirs, rvaToOff);
  if (directory.kind === "absent") return null;
  if (directory.kind === "invalid") return directory.result;
  const runtimeFunctions = await readAmd64RuntimeFunctions(
    reader,
    directory.directory.rva,
    directory.entryCount,
    rvaToOff,
    directory.issues
  );
  if (runtimeFunctions.functionCount === 0) {
    directory.issues.push("Exception directory does not contain a complete RUNTIME_FUNCTION entry.");
    return createEmptyExceptionDirectory(directory.issues, "amd64");
  }
  const unwindInfo = await scanAmd64UnwindInfos(
    reader,
    rvaToOff,
    runtimeFunctions.unwindRvas,
    directory.issues
  );
  return {
    functionCount: runtimeFunctions.functionCount,
    beginRvas: runtimeFunctions.beginRvas,
    handlerRvas: unwindInfo.handlerRvas,
    uniqueUnwindInfoCount: unwindInfo.uniqueUnwindInfoCount,
    unwindInfoVersion1Count: unwindInfo.unwindInfoVersion1Count,
    unwindInfoVersion2Count: unwindInfo.unwindInfoVersion2Count,
    epilogUnwindInfoCount: unwindInfo.epilogUnwindInfoCount,
    epilogScopeCount: unwindInfo.epilogScopeCount,
    handlerUnwindInfoCount: unwindInfo.handlerUnwindInfoCount,
    chainedUnwindInfoCount: unwindInfo.chainedUnwindInfoCount,
    invalidEntryCount: runtimeFunctions.invalidEntryCount,
    issues: directory.issues,
    format: "amd64"
  };
};
