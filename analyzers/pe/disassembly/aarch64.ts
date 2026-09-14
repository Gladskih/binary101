import { llvmVersion } from "llvm-aarch64-disasm";
import { loadAarch64Disassembler } from "#aarch64-disassembler-loader";
import { notifyAarch64Progress, walkAarch64ControlFlow } from "../../aarch64/control-flow.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection } from "../types.js";
import { peSectionNameValue } from "../sections/name.js";
import { isRvaField, PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { isMemoryExecutableSection, resolvePeDisassemblyEntrypoints } from "./sampling.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from "./types.js";

// PE/COFF: section RVAs and sizes are DWORDs; only raw bytes within VirtualSize are code.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const boundSections = (reader: FileRangeReader, sections: PeSection[], issues: string[]) =>
  sections.filter(isMemoryExecutableSection).flatMap(section => {
    const { virtualAddress, virtualSize, sizeOfRawData, pointerToRawData } = section;
    const size = Math.min(virtualSize || sizeOfRawData, sizeOfRawData);
    const label = peSectionNameValue(section.name);
    if (![virtualAddress, virtualSize, sizeOfRawData, pointerToRawData].every(isRvaField) ||
        virtualAddress + size > PE_RVA_EXCLUSIVE_LIMIT || pointerToRawData > reader.size) {
      issues.push(`${label} has an out-of-bounds file range or RVA.`);
      return [];
    }
    const available = Math.min(size, reader.size - pointerToRawData);
    if (available < size) issues.push(`${label} extends past end of file; truncating to available bytes.`);
    return available > 0 ? [{ ...section, virtualSize: available, sizeOfRawData: available }] : [];
  });

const createCodeReader = (
  reader: FileRangeReader, sections: PeSection[], imageBase: bigint
) => async (address: bigint): Promise<Uint8Array> => {
  const rva = address - imageBase;
  const section = sections.find(entry => rva >= BigInt(entry.virtualAddress) &&
    rva < BigInt(entry.virtualAddress + entry.sizeOfRawData));
  if (!section) return new Uint8Array();
  const offset = Number(rva) - section.virtualAddress;
  // Windows ARM64 is little endian; A64 instructions occupy four bytes.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions
  // Match the file-range reader's measured 64 KiB window, bounded by this section.
  return reader.readBytes(section.pointerToRawData + offset,
    Math.min(65536, section.sizeOfRawData - offset));
};

const resolveSeeds = (
  opts: AnalyzePeInstructionSetOptions, sections: PeSection[], issues: string[]
): bigint[] => resolvePeDisassemblyEntrypoints({ ...opts, sections }, issues).flatMap(rva => {
  if (!sections.some(section => rva >= section.virtualAddress &&
      rva < section.virtualAddress + section.sizeOfRawData)) {
    issues.push(`Skipped RVA 0x${rva.toString(16)} outside executable file-backed bytes.`);
    return [];
  }
  return [opts.imageBase + BigInt(rva)];
});

const analyzeCode = async (
  reader: FileRangeReader, opts: AnalyzePeInstructionSetOptions, report: PeInstructionSetReport
): Promise<void> => {
  // PE32+ ImageBase is an unsigned 8-byte field.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
  if (BigInt.asUintN(64, opts.imageBase) !== opts.imageBase) {
    report.issues.push("ImageBase is outside the 64-bit address range.");
    return;
  }
  if (!opts.is64Bit) report.issues.push("Machine is ARM64 but optional header reports 32-bit mode.");
  const sections = boundSections(reader, opts.sections, report.issues);
  report.bytesSampled = sections.reduce((sum, section) => sum + section.sizeOfRawData, 0);
  if (!sections.length) {
    report.issues.push("No executable bytes available for AArch64 disassembly.");
    return;
  }
  const seeds = resolveSeeds(opts, sections, report.issues);
  notifyAarch64Progress(opts, report, "loading");
  if (opts.signal?.aborted) {
    report.issues.push("Disassembly cancelled.");
    return;
  }
  await walkAarch64ControlFlow(await loadAarch64Disassembler(),
    createCodeReader(reader, sections, opts.imageBase), seeds, opts, report);
};

export const analyzePeAarch64InstructionSets = async (
  reader: FileRangeReader, opts: AnalyzePeInstructionSetOptions
): Promise<PeInstructionSetReport> => {
  const report: PeInstructionSetReport = {
    bitness: 64, decoderVersion: `LLVM ${llvmVersion}`, bytesSampled: 0, bytesDecoded: 0,
    instructionCount: 0, invalidInstructionCount: 0, instructionSets: [], issues: [],
    directIatReferences: [], codeStringReferences: [], apiStringReferences: [], specialInstructions: []
  };
  try {
    await analyzeCode(reader, opts, report);
  } catch (error) {
    report.issues.push(`AArch64 disassembly failed (${String(error)}).`);
  }
  notifyAarch64Progress(opts, report, "done");
  return report;
};
