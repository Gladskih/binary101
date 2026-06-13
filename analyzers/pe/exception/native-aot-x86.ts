"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeNativeAotCandidate } from "../native-aot.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "./runtime-spans.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

// dotnet/runtime NativeAOT COFF writer emits I386 .pdata rows as
// BeginAddress, EndAddress, and an x86 UNWIND_INFO RVA.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/ObjectWriter/CoffObjectWriter.Aot.cs
const NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
// dotnet/runtime win64unwind.h defines TARGET_X86 UNWIND_INFO as one ULONG
// FunctionLength; clrnt.h computes end as BeginAddress + FunctionLength.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/win64unwind.h
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/clrnt.h
const NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT;

type NativeAotX86RuntimeFunctionTable = {
  beginRvas: number[];
  functionCount: number;
  invalidEntryCount: number;
  unwindRvas: Set<number>;
};

const TRUNCATED_NATIVE_AOT_X86_RUNTIME_FUNCTION_ISSUE =
  "Exception directory is truncated; some NativeAOT x86 RuntimeFunction entries are missing.";

const formatHex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

const getMappedRvaIssue = (
  label: string,
  rva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): string | null => {
  const fileOffset = rvaToOff(rva);
  if (fileOffset == null) return `${label} ${formatHex(rva)} does not map to file data`;
  if (fileOffset < 0 || fileOffset >= fileSize) {
    return `${label} ${formatHex(rva)} maps outside the file`;
  }
  return null;
};

const addCountedIssue = (issues: Map<string, number>, issue: string): void => {
  issues.set(issue, (issues.get(issue) ?? 0) + 1);
};

const reportCountedIssues = (countedIssues: Map<string, number>, issues: string[]): void => {
  for (const [issue, count] of countedIssues) {
    issues.push(
      `${count} NativeAOT x86 RuntimeFunction ` +
        `${count === 1 ? "entry is" : "entries are"} invalid: ${issue}.`
    );
  }
};

const readX86UnwindFunctionLength = async (
  reader: FileRangeReader,
  unwindRva: number,
  rvaToOff: RvaToOffset
): Promise<number | string> => {
  const unwindOffset = rvaToOff(unwindRva);
  if (unwindOffset == null) return `UnwindData ${formatHex(unwindRva)} does not map to file data`;
  if (unwindOffset < 0 || unwindOffset >= reader.size) {
    return `UnwindData ${formatHex(unwindRva)} maps outside the file`;
  }
  if (unwindOffset + NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE > reader.size) {
    return `UnwindData ${formatHex(unwindRva)} is truncated`;
  }
  const view = await reader.read(unwindOffset, NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE);
  if (view.byteLength < NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE) {
    return `UnwindData ${formatHex(unwindRva)} is truncated`;
  }
  return view.getUint32(0, true) >>> 0;
};

const validateNativeAotX86RuntimeFunction = async (
  reader: FileRangeReader,
  beginRva: number,
  endRva: number,
  unwindRva: number,
  rvaToOff: RvaToOffset
): Promise<string[]> => {
  const issues: string[] = [];
  if (beginRva >= endRva) {
    issues.push("BeginAddress is greater than or equal to EndAddress");
    return issues;
  }
  const beginIssue = getMappedRvaIssue("BeginAddress", beginRva, rvaToOff, reader.size);
  const endIssue = getMappedRvaIssue("EndAddress", (endRva - 1) >>> 0, rvaToOff, reader.size);
  if (beginIssue) issues.push(beginIssue);
  if (endIssue) issues.push(endIssue);
  const functionLength = await readX86UnwindFunctionLength(reader, unwindRva, rvaToOff);
  if (typeof functionLength === "string") {
    issues.push(functionLength);
    return issues;
  }
  if (functionLength !== endRva - beginRva) {
    issues.push(
      `UNWIND_INFO FunctionLength ${functionLength} does not match ` +
        `EndAddress - BeginAddress ${endRva - beginRva}`
    );
  }
  return issues;
};

const readNativeAotX86RuntimeFunctions = async (
  reader: FileRangeReader,
  directory: PeDataDirectory,
  rvaToOff: RvaToOffset,
  issues: string[]
): Promise<NativeAotX86RuntimeFunctionTable> => {
  const beginRvas: number[] = [];
  const unwindRvas = new Set<number>();
  const invalidEntryIssues = new Map<string, number>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let previousBeginRva: number | null = null;
  let reportedUnsortedEntries = false;
  const entryCount = Math.floor(directory.size / NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE);
  const spans = collectRuntimeFunctionSpans(
    directory.rva,
    entryCount,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    reader.size,
    TRUNCATED_NATIVE_AOT_X86_RUNTIME_FUNCTION_ISSUE,
    issues
  );
  for (const span of spans) {
    const spanView = await readRuntimeFunctionSpan(
      reader,
      span,
      NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
      TRUNCATED_NATIVE_AOT_X86_RUNTIME_FUNCTION_ISSUE,
      issues
    );
    if (!spanView) break;
    const spanEntries = Math.floor(
      spanView.byteLength / NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE
    );
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const endRva = spanView.getUint32(entryOffset + Uint32Array.BYTES_PER_ELEMENT, true) >>> 0;
      const unwindRva = spanView.getUint32(
        entryOffset + Uint32Array.BYTES_PER_ELEMENT * 2,
        true
      ) >>> 0;
      functionCount += 1;
      const entryIssues = await validateNativeAotX86RuntimeFunction(
        reader,
        beginRva,
        endRva,
        unwindRva,
        rvaToOff
      );
      if (entryIssues.length) {
        invalidEntryCount += 1;
        entryIssues.forEach(issue => addCountedIssue(invalidEntryIssues, issue));
        continue;
      }
      beginRvas.push(beginRva);
      unwindRvas.add(unwindRva);
      if (previousBeginRva != null && beginRva < previousBeginRva && !reportedUnsortedEntries) {
        issues.push("NativeAOT x86 RuntimeFunction entries are not sorted by BeginAddress.");
        reportedUnsortedEntries = true;
      }
      previousBeginRva = beginRva;
    }
  }
  reportCountedIssues(invalidEntryIssues, issues);
  return { beginRvas, functionCount, invalidEntryCount, unwindRvas };
};

export const parseNativeAotX86ExceptionDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  nativeAotCandidate: PeNativeAotCandidate | null | undefined
): Promise<PeExceptionDirectory | null> => {
  if (nativeAotCandidate?.status !== "candidate") return null;
  const directory = dataDirs.find(candidate => candidate.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  if (directory.rva === 0) {
    return createEmptyExceptionDirectory(
      ["Exception directory has a non-zero size but RVA is 0."],
      "native-aot-x86"
    );
  }
  const base = rvaToOff(directory.rva);
  if (base == null) {
    return createEmptyExceptionDirectory(
      ["Exception directory RVA could not be mapped to a file offset."],
      "native-aot-x86"
    );
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExceptionDirectory(
      ["Exception directory location is outside the file."],
      "native-aot-x86"
    );
  }
  if (directory.size < NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE) {
    return createEmptyExceptionDirectory(
      [
        "Exception directory size is smaller than one NativeAOT x86 RuntimeFunction entry " +
          `(${NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
      ],
      "native-aot-x86"
    );
  }
  const issues: string[] = [];
  if (directory.size % NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push(
      "Exception directory size is not a multiple of NativeAOT x86 RuntimeFunction entry size " +
        `(${NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
    );
  }
  const runtimeTable = await readNativeAotX86RuntimeFunctions(reader, directory, rvaToOff, issues);
  if (runtimeTable.functionCount === 0) {
    issues.push(
      "Exception directory does not contain a complete NativeAOT x86 RuntimeFunction entry."
    );
    return createEmptyExceptionDirectory(issues, "native-aot-x86");
  }
  return {
    functionCount: runtimeTable.functionCount,
    beginRvas: runtimeTable.beginRvas,
    handlerRvas: [],
    uniqueUnwindInfoCount: runtimeTable.unwindRvas.size,
    handlerUnwindInfoCount: 0,
    chainedUnwindInfoCount: 0,
    invalidEntryCount: runtimeTable.invalidEntryCount,
    issues,
    format: "native-aot-x86"
  };
};
