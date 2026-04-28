"use strict";

import type { PeDataDirectory, RvaToOffset } from "../../types.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "../types.js";

// Microsoft PE format, ".pdata (Exception Information)":
// each x64 RUNTIME_FUNCTION entry is 12 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
export const AMD64_RUNTIME_FUNCTION_ENTRY_SIZE = 12;

export type Amd64ExceptionDirectoryResolution =
  | { kind: "absent" }
  | { kind: "invalid"; result: PeExceptionDirectory }
  | { kind: "valid"; directory: PeDataDirectory; entryCount: number; issues: string[] };

export const resolveAmd64ExceptionDirectory = (
  readerSize: number,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Amd64ExceptionDirectoryResolution => {
  const directory = dataDirs.find(candidate => candidate.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return { kind: "absent" };
  if (directory.rva === 0) {
    return {
      kind: "invalid",
      result: createEmptyExceptionDirectory(
        ["Exception directory has a non-zero size but RVA is 0."],
        "amd64"
      )
    };
  }
  const fileOffset = rvaToOff(directory.rva);
  if (fileOffset == null) {
    return {
      kind: "invalid",
      result: createEmptyExceptionDirectory(
        ["Exception directory RVA could not be mapped to a file offset."],
        "amd64"
      )
    };
  }
  if (fileOffset < 0 || fileOffset >= readerSize) {
    return {
      kind: "invalid",
      result: createEmptyExceptionDirectory(
        ["Exception directory location is outside the file."],
        "amd64"
      )
    };
  }
  if (directory.size < AMD64_RUNTIME_FUNCTION_ENTRY_SIZE) {
    return {
      kind: "invalid",
      result: createEmptyExceptionDirectory(
        [
          `Exception directory size is smaller than one RUNTIME_FUNCTION entry (${AMD64_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
        ],
        "amd64"
      )
    };
  }
  const issues: string[] = [];
  if (directory.size % AMD64_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push("Exception directory size is not a multiple of RUNTIME_FUNCTION entry size (12 bytes).");
  }
  return {
    kind: "valid",
    directory,
    entryCount: Math.floor(directory.size / AMD64_RUNTIME_FUNCTION_ENTRY_SIZE),
    issues
  };
};
