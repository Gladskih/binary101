import type { FileRangeReader } from "../../file-range-reader.js";
import { IMAGE_FILE_MACHINE_ARMNT } from "../../coff/machine.js";
import type { PeWindowsParseResult } from "../core/parse-result.js";
import { getCanonicalPeMachine } from "../machine.js";
import { findSectionContainingRva, isMemoryExecutableSection } from "../disassembly/sampling.js";
import { isRvaRange, mappedRvaSpan } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { PeClrReadyToRunSection } from "./ready-to-run-types.js";
import { readyToRunRuntimeFunctionSize } from "./ready-to-run-target.js";

const isFileBackedCode = (rva: number, pe: PeWindowsParseResult, fileSize: number): boolean => {
  if (!rva || rva >= pe.opt.SizeOfImage) return false;
  const section = findSectionContainingRva(pe.sections, rva);
  return section != null && isMemoryExecutableSection(section) &&
    rva - section.virtualAddress < section.sizeOfRawData &&
    mappedRvaSpan(pe.rvaToOff, rva, 1, fileSize) != null;
};

const readRuntimeFunctionStart = (
  view: DataView, offset: number, pe: PeWindowsParseResult, fileSize: number
): number => {
  // ReadyToRunMethod.ParseRuntimeFunctions: StartAddress is the first DWORD;
  // ARMNT sets bit 0 for Thumb code, so clear it before treating the value as an RVA.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunMethod.cs#L549-L555
  const address = view.getUint32(offset, true);
  const rva = getCanonicalPeMachine(pe.coff.Machine) === IMAGE_FILE_MACHINE_ARMNT
    ? address - address % 2 : address;
  if (!isFileBackedCode(rva, pe, fileSize)) {
    throw new Error("runtime-function start does not map to file-backed executable code");
  }
  return rva;
};

const collectRuntimeFunctionStarts = async (
  reader: FileRangeReader, pe: PeWindowsParseResult, table: PeClrReadyToRunSection,
  indices: Set<number>, width: number, issues: string[]
): Promise<number[]> => {
  const rvas = new Set<number>();
  const warnings = new Set<string>();
  const count = Math.floor(table.size / width);
  validateMethodIndices(indices, count, warnings);
  // A bounded I/O buffer, not a record limit: visit every complete RuntimeFunctions record.
  // Cold blocks and funclets may not have their own MethodDef/InstanceMethod entrypoint.
  const chunkRows = Math.floor(64 * 1024 / width);
  for (let first = 0; first < count; first += chunkRows) {
    const rows = Math.min(chunkRows, count - first);
    const view = await readRuntimeChunk(reader, pe, table.rva + first * width, rows * width, width, warnings);
    for (let offset = 0; offset + width <= view.byteLength; offset += width) {
      try { rvas.add(readRuntimeFunctionStart(view, offset, pe, reader.size)); }
      catch (error) { warnings.add(error instanceof Error ? error.message : "runtime-function read failed"); }
    }
    if (view.byteLength < rows * width) {
      warnings.add("runtime-function entry is truncated or unmapped");
      break;
    }
  }
  issues.push(...[...warnings].map(message => `ReadyToRun disassembly seeds: ${message}.`));
  return [...rvas];
};

const validateMethodIndices = (indices: Set<number>, count: number, warnings: Set<string>): void => {
  for (const index of indices) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
      warnings.add("method map references a missing runtime-function index");
    }
  }
};

const readRuntimeChunk = async (reader: FileRangeReader, pe: PeWindowsParseResult,
  rva: number, size: number, width: number, warnings: Set<string>): Promise<DataView> => {
  try { return await readMappedRvaPrefix(reader, rva, size, pe.rvaToOff); }
  catch (error) {
    warnings.add(error instanceof Error ? error.message : "runtime-function read failed");
    return recoverRuntimeChunk(reader, pe, rva, size, width, warnings);
  }
};

const recoverRuntimeChunk = async (reader: FileRangeReader, pe: PeWindowsParseResult,
  rva: number, size: number, width: number, warnings: Set<string>): Promise<DataView> => {
  const bytes = new Uint8Array(size);
  let readable = 0;
  for (let offset = 0; offset < size; offset += width) {
    if (!mappedRvaSpan(pe.rvaToOff, rva + offset, width, reader.size)) break;
    try {
      const view = await readMappedRvaPrefix(reader, rva + offset, width, pe.rvaToOff);
      if (view.byteLength !== width) break;
      bytes.set(new Uint8Array(view.buffer, view.byteOffset, width), offset);
      readable = offset + width;
    } catch (error) {
      recordReadFailure(error, warnings);
    }
  }
  return new DataView(bytes.buffer, 0, readable);
};

const recordReadFailure = (error: unknown, warnings: Set<string>): void => {
  warnings.add(error instanceof Error ? error.message : "runtime-function read failed");
};

const collectMethodIndices = (sections: PeClrReadyToRunSection[]): Set<number> => {
  const indices = new Set<number>();
  // readytorun.h: MethodDefEntryPoints = 103, InstanceMethodEntryPoints = 109.
  for (const section of sections) {
    if ((section.type === 103 || section.type === 109) &&
      (section.decoded?.kind === "methods" || section.decoded?.kind === "instance-methods")) {
      section.decoded.methods.forEach(method => indices.add(method.runtimeFunctionIndex));
    }
  }
  return indices;
};

export const collectReadyToRunMethodRvas = async (
  reader: FileRangeReader, pe: PeWindowsParseResult, issues: string[]
): Promise<number[]> => {
  const readyToRun = pe.clr?.readyToRun;
  if (readyToRun?.status !== "ready-to-run") return [];
  // readytorun.h: MethodDefEntryPoints = 103, RuntimeFunctions = 102.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  const indices = collectMethodIndices(readyToRun.sections);
  const table = runtimeTable(readyToRun.sections, indices.size, issues);
  if (!table) return [];
  const width = readyToRunRuntimeFunctionSize(pe.coff.Machine);
  if (!width) {
    issues.push("ReadyToRun disassembly seeds: runtime-function layout is unknown for this machine.");
    return [];
  }
  if (!isRvaRange(table.rva, table.size)) {
    issues.push("ReadyToRun disassembly seeds: RuntimeFunctions has an invalid RVA range.");
    return [];
  }
  if (table.size % width) {
    issues.push("ReadyToRun disassembly seeds: RuntimeFunctions ends with an incomplete entry.");
  }
  return collectRuntimeFunctionStarts(reader, pe, table, indices, width, issues);
};

const runtimeTable = (sections: PeClrReadyToRunSection[], methodCount: number,
  issues: string[]): PeClrReadyToRunSection | undefined => {
  const tables = sections.filter(section => section.type === 102);
  if (!methodCount && !tables.length) return undefined;
  if (tables.length === 1) return tables[0];
  issues.push("ReadyToRun disassembly seeds: RuntimeFunctions section is missing or ambiguous.");
  return undefined;
};
