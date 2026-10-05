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

const readRuntimeFunctionStart = async (
  reader: FileRangeReader, pe: PeWindowsParseResult,
  table: PeClrReadyToRunSection, index: number, width: number
): Promise<number> => {
  if (!Number.isSafeInteger(index) || index < 0 || index >= Math.floor(table.size / width)) {
    throw new Error("method map references a missing runtime-function index");
  }
  const view = await readMappedRvaPrefix(reader, table.rva + index * width, width, pe.rvaToOff);
  if (view.byteLength !== width) throw new Error("runtime-function entry is truncated or unmapped");
  // ReadyToRunMethod.ParseRuntimeFunctions: StartAddress is the first DWORD;
  // ARMNT sets bit 0 for Thumb code, so clear it before treating the value as an RVA.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunMethod.cs#L549-L555
  const address = view.getUint32(0, true);
  const rva = getCanonicalPeMachine(pe.coff.Machine) === IMAGE_FILE_MACHINE_ARMNT
    ? address - address % 2 : address;
  if (!isFileBackedCode(rva, pe, reader.size)) {
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
  // Visit each referenced record once, in table order, to reuse the bounded read cache.
  for (const index of [...indices].sort((left, right) => left - right)) {
    try {
      rvas.add(await readRuntimeFunctionStart(reader, pe, table, index, width));
    } catch (error) {
      warnings.add(`ReadyToRun disassembly seeds: ${
        error instanceof Error ? error.message : "runtime-function read failed"}.`);
    }
  }
  issues.push(...warnings);
  return [...rvas];
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
  if (!indices.size) return [];
  const tables = readyToRun.sections.filter(section => section.type === 102);
  if (tables.length !== 1) {
    issues.push("ReadyToRun disassembly seeds: RuntimeFunctions section is missing or ambiguous.");
    return [];
  }
  const width = readyToRunRuntimeFunctionSize(pe.coff.Machine);
  if (!width) {
    issues.push("ReadyToRun disassembly seeds: runtime-function layout is unknown for this machine.");
    return [];
  }
  const table = tables[0]!;
  if (!isRvaRange(table.rva, table.size)) {
    issues.push("ReadyToRun disassembly seeds: RuntimeFunctions has an invalid RVA range.");
    return [];
  }
  if (table.size % width) {
    issues.push("ReadyToRun disassembly seeds: RuntimeFunctions ends with an incomplete entry.");
  }
  return collectRuntimeFunctionStarts(reader, pe, table, indices, width, issues);
};
