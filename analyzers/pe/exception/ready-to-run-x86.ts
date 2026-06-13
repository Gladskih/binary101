"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS,
  type PeClrReadyToRun,
  type PeClrReadyToRunSection
} from "../clr/ready-to-run-types.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { readReadyToRunExceptionInfo } from "./ready-to-run-exception-info.js";
import { collectRuntimeFunctionSpans, readRuntimeFunctionSpan } from "./runtime-spans.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

// dotnet/runtime ReadyToRun writer emits non-AMD64 RuntimeFunctions as the code
// start RVA followed by the RuntimeFunctionsGCInfo RVA; ReadyToRunReader reads
// I386 rows as StartAddress/UnwindRVA and derives the function length from the
// x86 unwind/GC info.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/RuntimeFunctionsTableNode.cs
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunMethod.cs
const R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE = 8;

type R2rRuntimeFunctionTable = {
  beginRvas: number[];
  functionCount: number;
  invalidEntryCount: number;
  unwindRvas: Set<number>;
};

const formatHex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

const findReadyToRunSection = (
  readyToRun: PeClrReadyToRun,
  sectionType: number
): PeClrReadyToRunSection | null =>
  readyToRun.sections.find(section => section.type === sectionType) ?? null;

const isSameDirectoryRange = (
  directory: PeDataDirectory,
  section: PeClrReadyToRunSection | null
): section is PeClrReadyToRunSection =>
  section != null && directory.rva === section.rva && directory.size === section.size;

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

const addCountedIssue = (
  invalidEntryIssues: Map<string, number>,
  issue: string
): void => {
  invalidEntryIssues.set(issue, (invalidEntryIssues.get(issue) ?? 0) + 1);
};

const reportCountedIssues = (
  invalidEntryIssues: Map<string, number>,
  issues: string[]
): void => {
  for (const [issue, count] of invalidEntryIssues) {
    issues.push(
      `${count} ReadyToRun x86 RuntimeFunction entr${count === 1 ? "y is" : "ies are"} invalid: ${issue}.`
    );
  }
};

const readReadyToRunX86RuntimeFunctions = async (
  reader: FileRangeReader,
  directory: PeDataDirectory,
  rvaToOff: RvaToOffset,
  issues: string[]
): Promise<R2rRuntimeFunctionTable> => {
  const beginRvas: number[] = [];
  const unwindRvas = new Set<number>();
  const invalidEntryIssues = new Map<string, number>();
  let functionCount = 0;
  let invalidEntryCount = 0;
  let previousBeginRva: number | null = null;
  let reportedUnsortedEntries = false;
  const entryCount = Math.floor(directory.size / R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE);
  const spans = collectRuntimeFunctionSpans(
    directory.rva,
    entryCount,
    R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    rvaToOff,
    reader.size,
    "Exception directory is truncated; some ReadyToRun x86 RuntimeFunction entries are missing.",
    issues
  );
  for (const span of spans) {
    const spanView = await readRuntimeFunctionSpan(
      reader,
      span,
      R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
      "Exception directory is truncated; some ReadyToRun x86 RuntimeFunction entries are missing.",
      issues
    );
    if (!spanView) break;
    const spanEntries = Math.floor(spanView.byteLength / R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE);
    for (let index = 0; index < spanEntries; index += 1) {
      const entryOffset = index * R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE;
      const beginRva = spanView.getUint32(entryOffset, true) >>> 0;
      const unwindRva = spanView.getUint32(entryOffset + Uint32Array.BYTES_PER_ELEMENT, true) >>> 0;
      functionCount += 1;
      const beginIssue = getMappedRvaIssue("BeginAddress", beginRva, rvaToOff, reader.size);
      const unwindIssue = getMappedRvaIssue("UnwindData", unwindRva, rvaToOff, reader.size);
      if (beginIssue || unwindIssue) {
        invalidEntryCount += 1;
        if (beginIssue) addCountedIssue(invalidEntryIssues, beginIssue);
        if (unwindIssue) addCountedIssue(invalidEntryIssues, unwindIssue);
        continue;
      }
      beginRvas.push(beginRva);
      unwindRvas.add(unwindRva);
      if (previousBeginRva != null && beginRva < previousBeginRva && !reportedUnsortedEntries) {
        issues.push("ReadyToRun x86 RuntimeFunction entries are not sorted by BeginAddress.");
        reportedUnsortedEntries = true;
      }
      previousBeginRva = beginRva;
    }
  }
  reportCountedIssues(invalidEntryIssues, issues);
  return { beginRvas, functionCount, invalidEntryCount, unwindRvas };
};

export const parseReadyToRunX86ExceptionDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readyToRun: PeClrReadyToRun | null | undefined
): Promise<PeExceptionDirectory | null> => {
  if (readyToRun?.status !== "ready-to-run") return null;
  const directory = dataDirs.find(candidate => candidate.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  const runtimeFunctions = findReadyToRunSection(readyToRun, READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS);
  if (!isSameDirectoryRange(directory, runtimeFunctions)) return null;
  if (directory.rva === 0) {
    return createEmptyExceptionDirectory(
      ["Exception directory has a non-zero size but RVA is 0."],
      "ready-to-run-x86"
    );
  }
  const base = rvaToOff(directory.rva);
  if (base == null) {
    return createEmptyExceptionDirectory(
      ["Exception directory RVA could not be mapped to a file offset."],
      "ready-to-run-x86"
    );
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyExceptionDirectory(
      ["Exception directory location is outside the file."],
      "ready-to-run-x86"
    );
  }
  if (directory.size < R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE) {
    return createEmptyExceptionDirectory(
      [
        "Exception directory size is smaller than one ReadyToRun x86 RuntimeFunction entry " +
          `(${R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
      ],
      "ready-to-run-x86"
    );
  }
  const issues: string[] = [];
  if (directory.size % R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE !== 0) {
    issues.push(
      "Exception directory size is not a multiple of ReadyToRun x86 RuntimeFunction entry size " +
        `(${R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE} bytes).`
    );
  }
  const runtimeTable = await readReadyToRunX86RuntimeFunctions(reader, directory, rvaToOff, issues);
  if (runtimeTable.functionCount === 0) {
    issues.push("Exception directory does not contain a complete ReadyToRun x86 RuntimeFunction entry.");
    return createEmptyExceptionDirectory(issues, "ready-to-run-x86");
  }
  const exceptionInfo = await readReadyToRunExceptionInfo(
    reader,
    readyToRun,
    new Set(runtimeTable.beginRvas),
    rvaToOff,
    issues
  );
  return {
    functionCount: runtimeTable.functionCount,
    beginRvas: runtimeTable.beginRvas,
    handlerRvas: exceptionInfo.handlerRvas,
    uniqueUnwindInfoCount: runtimeTable.unwindRvas.size,
    handlerUnwindInfoCount: exceptionInfo.exceptionClauseCount,
    chainedUnwindInfoCount: 0,
    invalidEntryCount: runtimeTable.invalidEntryCount,
    issues,
    format: "ready-to-run-x86",
    exceptionInfoMethodCount: exceptionInfo.exceptionInfoMethodCount,
    exceptionClauseCount: exceptionInfo.exceptionClauseCount,
    catchClauseCount: exceptionInfo.catchClauseCount,
    filterClauseCount: exceptionInfo.filterClauseCount,
    finallyClauseCount: exceptionInfo.finallyClauseCount,
    faultClauseCount: exceptionInfo.faultClauseCount
  };
};
