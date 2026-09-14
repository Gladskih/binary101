import { llvmVersion } from "llvm-aarch64-disasm";
import { loadAarch64Disassembler } from "#aarch64-disassembler-loader";
import { createFileRangeReader } from "../file-range-reader.js";
import { notifyAarch64Progress, walkAarch64ControlFlow } from "../aarch64/control-flow.js";
import type { AnalyzeElfInstructionSetOptions, ElfInstructionSetReport } from "./disassembly-types.js";
import { collectElfInstructionSetSeeds } from "./disassembly-entrypoints.js";
import { getElfExecutableRegions, findElfRegionContainingVaddr, type ElfExecutableRegion } from "./executable-regions.js";

const boundRegions = (file: File, opts: AnalyzeElfInstructionSetOptions, issues: string[]) =>
  getElfExecutableRegions(opts.programHeaders, opts.sections).flatMap(region => {
    if (region.fileOffset < 0n || region.fileOffset >= BigInt(file.size) ||
        region.vaddr < 0n || region.vaddr + region.fileSize > 0x1_0000_0000_0000_0000n) {
      issues.push(`${region.label} has an out-of-bounds file range or virtual address.`);
      return [];
    }
    const available = BigInt(file.size) - region.fileOffset;
    if (region.fileSize <= available) return [region];
    issues.push(`${region.label} extends past end of file; truncating to available bytes.`);
    return [{ ...region, fileSize: available }];
  });

const createCodeReader = (file: File, regions: ElfExecutableRegion[]) => {
  const reader = createFileRangeReader(file, 0, file.size);
  return async (address: bigint): Promise<Uint8Array> => {
    const region = findElfRegionContainingVaddr(regions, address);
    if (!region) return new Uint8Array();
    const offset = address - region.vaddr;
    // A64 words are always little endian, even for big endian ELF data.
    // https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
    // Match the file-range reader's measured 64 KiB window, bounded by this region.
    return reader.readBytes(Number(region.fileOffset + offset),
      Number(region.fileSize - offset < 65536n ? region.fileSize - offset : 65536n));
  };
};

export const analyzeAarch64InstructionSets = async (
  file: File,
  opts: AnalyzeElfInstructionSetOptions
): Promise<ElfInstructionSetReport> => {
  const report: ElfInstructionSetReport = {
    bitness: 64, decoderVersion: `LLVM ${llvmVersion}`, bytesSampled: 0, bytesDecoded: 0,
    instructionCount: 0, invalidInstructionCount: 0, instructionSets: [], issues: []
  };
  try {
    await analyzeCode(file, opts, report);
  } catch (error) {
    report.issues.push(`AArch64 disassembly failed (${String(error)}).`);
  }
  notifyAarch64Progress(opts, report, "done");
  return report;
};

const analyzeCode = async (
  file: File, opts: AnalyzeElfInstructionSetOptions, report: ElfInstructionSetReport
): Promise<void> => {
  const regions = boundRegions(file, opts, report.issues);
  report.bytesSampled = regions.reduce((sum, region) => sum + Number(region.fileSize), 0);
  if (!regions.length) {
    report.issues.push("No executable bytes available for AArch64 disassembly.");
    return;
  }
  const seeds = await collectElfInstructionSetSeeds(file, opts, regions,
    regions.map(region => ({ vaddrStart: region.vaddr, label: region.label })), report.issues);
  if (!seeds) return;
  report.seedSummary = seeds.seedSummary;
  notifyAarch64Progress(opts, report, "loading");
  if (opts.signal?.aborted) {
    report.issues.push("Disassembly cancelled.");
    return;
  }
  await walkAarch64ControlFlow(await loadAarch64Disassembler(), createCodeReader(file, regions),
    seeds.entrypoints, opts, report);
};
