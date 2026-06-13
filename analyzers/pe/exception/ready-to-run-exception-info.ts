"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  READY_TO_RUN_SECTION_EXCEPTION_INFO,
  type PeClrReadyToRun,
  type PeClrReadyToRunSection
} from "../clr/ready-to-run-types.js";
import type { RvaToOffset } from "../types.js";

// dotnet/runtime readytorun.h:
// READYTORUN_EXCEPTION_LOOKUP_TABLE_ENTRY is two DWORDs.
// READYTORUN_EXCEPTION_CLAUSE is CorExceptionFlag plus five DWORD fields.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
const R2R_EXCEPTION_LOOKUP_ENTRY_SIZE = 8;
const R2R_EXCEPTION_CLAUSE_SIZE = 24;

// CoreCLR CorExceptionFlag values mirror ECMA-335 exception clause flags.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
const COR_ILEXCEPTION_CLAUSE_FILTER = 0x0001;
const COR_ILEXCEPTION_CLAUSE_FINALLY = 0x0002;
const COR_ILEXCEPTION_CLAUSE_FAULT = 0x0004;
const COR_ILEXCEPTION_CLAUSE_KIND_MASK =
  COR_ILEXCEPTION_CLAUSE_FILTER |
  COR_ILEXCEPTION_CLAUSE_FINALLY |
  COR_ILEXCEPTION_CLAUSE_FAULT;

type R2rExceptionLookupEntry = {
  exceptionInfoRva: number;
  methodStartRva: number;
  methodStartMaps: boolean;
};

export type R2rExceptionInfo = {
  catchClauseCount: number;
  exceptionClauseCount: number;
  exceptionInfoMethodCount: number;
  faultClauseCount: number;
  filterClauseCount: number;
  finallyClauseCount: number;
  handlerRvas: number[];
  methodStartRvas: number[];
};

const formatHex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

const findReadyToRunSection = (
  readyToRun: PeClrReadyToRun,
  sectionType: number
): PeClrReadyToRunSection | null =>
  readyToRun.sections.find(section => section.type === sectionType) ?? null;

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

const readMappedSection = async (
  reader: FileRangeReader,
  section: PeClrReadyToRunSection,
  rvaToOff: RvaToOffset,
  issues: string[],
  label: string
): Promise<DataView | null> => {
  const offset = rvaToOff(section.rva);
  if (offset == null) {
    issues.push(`${label} RVA could not be mapped to a file offset.`);
    return null;
  }
  if (offset < 0 || offset >= reader.size) {
    issues.push(`${label} location is outside the file.`);
    return null;
  }
  const readableSize = Math.min(section.size, reader.size - offset);
  const view = await reader.read(offset, readableSize);
  if (view.byteLength < section.size) {
    issues.push(`${label} is truncated.`);
  }
  return view;
};

const readExceptionLookupEntries = (
  view: DataView,
  rvaToOff: RvaToOffset,
  readerSize: number,
  issues: string[]
): R2rExceptionLookupEntry[] => {
  // dotnet/runtime ExceptionInfoLookupTableNode emits a final sentinel row with
  // MethodStart = -1 and ExceptionInfo pointing to the end of the EH info block.
  // ReadyToRunReader consumes pairs of current/next rows to size each clause array.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/ExceptionInfoLookupTableNode.cs
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
  const entries: R2rExceptionLookupEntry[] = [];
  const entryCount = Math.floor(view.byteLength / R2R_EXCEPTION_LOOKUP_ENTRY_SIZE);
  for (let index = 0; index < entryCount; index += 1) {
    const offset = index * R2R_EXCEPTION_LOOKUP_ENTRY_SIZE;
    const methodStartRva = view.getUint32(offset, true) >>> 0;
    entries.push({
      exceptionInfoRva: view.getUint32(offset + Uint32Array.BYTES_PER_ELEMENT, true) >>> 0,
      methodStartMaps: getMappedRvaIssue("MethodStart", methodStartRva, rvaToOff, readerSize) == null,
      methodStartRva
    });
  }
  if (view.byteLength % R2R_EXCEPTION_LOOKUP_ENTRY_SIZE !== 0) {
    issues.push(
      "ReadyToRun ExceptionInfo section size is not a multiple of lookup entry size " +
        `(${R2R_EXCEPTION_LOOKUP_ENTRY_SIZE} bytes).`
    );
  }
  return entries;
};

const addUniqueRva = (values: number[], seen: Set<number>, rva: number): void => {
  const normalized = rva >>> 0;
  if (seen.has(normalized)) return;
  seen.add(normalized);
  values.push(normalized);
};

const addClauseKind = (
  flags: number,
  stats: Pick<
    R2rExceptionInfo,
    "catchClauseCount" | "faultClauseCount" | "filterClauseCount" | "finallyClauseCount"
  >,
  issues: string[]
): void => {
  // ReadyToRun/NGen may carry implementation-specific high bits in CorExceptionFlag.
  // Only the ECMA/CoreCLR low handler-kind bits are used to classify the clause.
  const kind = flags & COR_ILEXCEPTION_CLAUSE_KIND_MASK;
  if (kind === 0) {
    stats.catchClauseCount += 1;
  } else if (kind === COR_ILEXCEPTION_CLAUSE_FILTER) {
    stats.filterClauseCount += 1;
  } else if (kind === COR_ILEXCEPTION_CLAUSE_FINALLY) {
    stats.finallyClauseCount += 1;
  } else if (kind === COR_ILEXCEPTION_CLAUSE_FAULT) {
    stats.faultClauseCount += 1;
  } else {
    issues.push(`ReadyToRun exception clause combines mutually exclusive handler flags: ${formatHex(flags)}.`);
  }
};

const countClausesForEntry = async (
  reader: FileRangeReader,
  current: R2rExceptionLookupEntry,
  next: R2rExceptionLookupEntry,
  rvaToOff: RvaToOffset,
  stats: R2rExceptionInfo,
  handlerRvasSeen: Set<number>,
  issues: string[]
): Promise<void> => {
  if (!current.methodStartMaps) return;
  const startRva = current.exceptionInfoRva;
  const endRva = next.exceptionInfoRva;
  if (endRva < startRva) {
    issues.push("ReadyToRun ExceptionInfo clause arrays are not sorted by RVA.");
    return;
  }
  const byteLength = endRva - startRva;
  if (byteLength % R2R_EXCEPTION_CLAUSE_SIZE !== 0) {
    issues.push("ReadyToRun exception clause array size is not a multiple of READYTORUN_EXCEPTION_CLAUSE size.");
    return;
  }
  if (byteLength === 0) return;
  const offset = rvaToOff(startRva);
  if (offset == null || offset < 0 || offset >= reader.size) {
    issues.push(`ReadyToRun exception clause array ${formatHex(startRva)} does not map to file data.`);
    return;
  }
  const readableSize = Math.min(byteLength, reader.size - offset);
  const view = await reader.read(offset, readableSize);
  if (view.byteLength < byteLength) {
    issues.push("ReadyToRun exception clause array is truncated.");
    return;
  }
  const clauseCount = byteLength / R2R_EXCEPTION_CLAUSE_SIZE;
  for (let index = 0; index < clauseCount; index += 1) {
    const clauseOffset = index * R2R_EXCEPTION_CLAUSE_SIZE;
    const flags = view.getUint32(clauseOffset, true) >>> 0;
    const handlerStartPc = view.getUint32(clauseOffset + Uint32Array.BYTES_PER_ELEMENT * 3, true) >>> 0;
    stats.exceptionClauseCount += 1;
    addClauseKind(flags, stats, issues);
    const handlerRva = (current.methodStartRva + handlerStartPc) >>> 0;
    if (getMappedRvaIssue("HandlerStartPC", handlerRva, rvaToOff, reader.size) == null) {
      addUniqueRva(stats.handlerRvas, handlerRvasSeen, handlerRva);
    }
  }
};

export const readReadyToRunExceptionInfo = async (
  reader: FileRangeReader,
  readyToRun: PeClrReadyToRun,
  runtimeBeginRvas: Set<number>,
  rvaToOff: RvaToOffset,
  issues: string[]
): Promise<R2rExceptionInfo> => {
  const stats: R2rExceptionInfo = {
    catchClauseCount: 0,
    exceptionClauseCount: 0,
    exceptionInfoMethodCount: 0,
    faultClauseCount: 0,
    filterClauseCount: 0,
    finallyClauseCount: 0,
    handlerRvas: [],
    methodStartRvas: []
  };
  const exceptionInfoSection = findReadyToRunSection(readyToRun, READY_TO_RUN_SECTION_EXCEPTION_INFO);
  if (!exceptionInfoSection || exceptionInfoSection.size === 0) return stats;
  const view = await readMappedSection(
    reader,
    exceptionInfoSection,
    rvaToOff,
    issues,
    "ReadyToRun ExceptionInfo section"
  );
  if (!view) return stats;
  const entries = readExceptionLookupEntries(view, rvaToOff, reader.size, issues);
  const methodStartSeen = new Set<number>();
  const handlerRvasSeen = new Set<number>();
  let previousMethodStart: number | null = null;
  for (const entry of entries) {
    if (!entry.methodStartMaps) continue;
    stats.exceptionInfoMethodCount += 1;
    addUniqueRva(stats.methodStartRvas, methodStartSeen, entry.methodStartRva);
    if (!runtimeBeginRvas.has(entry.methodStartRva)) {
      issues.push(
        `ReadyToRun ExceptionInfo MethodStart ${formatHex(entry.methodStartRva)} is not present in RuntimeFunctions.`
      );
    }
    if (previousMethodStart != null && entry.methodStartRva < previousMethodStart) {
      issues.push("ReadyToRun ExceptionInfo entries are not sorted by MethodStart.");
    }
    previousMethodStart = entry.methodStartRva;
  }
  for (let index = 0; index + 1 < entries.length; index += 1) {
    await countClausesForEntry(reader, entries[index]!, entries[index + 1]!, rvaToOff, stats, handlerRvasSeen, issues);
  }
  return stats;
};
