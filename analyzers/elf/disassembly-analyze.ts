"use strict";

import type {
  AnalyzeElfInstructionSetOptions,
  ElfDisassemblySeedSummary,
  ElfInstructionSetProgress,
  ElfInstructionSetReport
} from "./disassembly-types.js";
import { getElfExecutableRegions } from "./executable-regions.js";
import { disassembleControlFlowForInstructionSetsVaddr } from "../x86/disassembly-control-flow-vaddr.js";
import { isIcedX86Module, type IcedX86Module } from "../x86/disassembly-iced.js";
import { loadIcedX86 } from "#iced-x86-loader";
import { createX86InstructionSetUsageTracker } from "../x86/instruction-set-usage.js";
import { collectElfInstructionSetSeeds } from "./disassembly-entrypoints.js";
import { sampleElfExecutableRegions, type ElfSampledSection } from "./disassembly-sampling.js";

const ELF_MACHINE_I386 = 3;
const ELF_MACHINE_X86_64 = 62;

type ElfInstructionSetDecodeRun = {
  iced: IcedX86Module;
  bitness: 32 | 64;
  sampledSections: ElfSampledSection[];
  entrypoints: bigint[];
  yieldEveryInstructions: number;
  bytesSampled: number;
  issues: string[];
  opts: AnalyzeElfInstructionSetOptions;
};

type ElfInstructionSetDecodeResult = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: ElfInstructionSetReport["instructionSets"];
};

const reportProgress = (opts: AnalyzeElfInstructionSetOptions, progress: ElfInstructionSetProgress): void => {
  if (!opts.onProgress) return;
  try {
    opts.onProgress(progress);
  } catch {
    // Progress callbacks are UI-facing; analysis should continue even if a consumer throws.
  }
};

const yieldToEventLoop = async (): Promise<void> => new Promise<void>(resolve => setTimeout(resolve, 0));

export async function analyzeElfInstructionSets(
  file: File,
  opts: AnalyzeElfInstructionSetOptions
): Promise<ElfInstructionSetReport> {
  const issues: string[] = [];
  const machine = opts.machine >>> 0;
  const supported = machine === ELF_MACHINE_I386 || machine === ELF_MACHINE_X86_64;
  const bitness: 32 | 64 = opts.is64Bit ? 64 : 32;
  const yieldEveryInstructions =
    typeof opts.yieldEveryInstructions === "number" &&
    Number.isSafeInteger(opts.yieldEveryInstructions) &&
    opts.yieldEveryInstructions > 0
      ? opts.yieldEveryInstructions
      : 0;
  const emptyReport = (bytesSampled: number, seedSummary?: ElfDisassemblySeedSummary): ElfInstructionSetReport => ({
    bitness,
    bytesSampled,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    instructionSets: [],
    issues,
    ...(seedSummary ? { seedSummary } : {})
  });
  if (!supported) {
    issues.push(`Disassembly is only supported for x86/x86-64 (e_machine ${machine}).`);
    return emptyReport(0);
  }
  if (!opts.littleEndian) {
    issues.push("Big-endian ELF is not supported for x86/x86-64 disassembly.");
  }
  if (machine === ELF_MACHINE_X86_64 && bitness !== 64) {
    issues.push("Machine is x86-64 but ELF class reports 32-bit mode.");
  } else if (machine === ELF_MACHINE_I386 && bitness !== 32) {
    issues.push("Machine is i386 but ELF class reports 64-bit mode.");
  }
  const regions = getElfExecutableRegions(opts.programHeaders, opts.sections);
  if (!regions.length) {
    issues.push("No executable segments/sections available to locate code bytes.");
    return emptyReport(0);
  }
  const sampledSections = await sampleElfExecutableRegions(file, regions, issues);
  const bytesSampled = sampledSections.reduce((sum, entry) => sum + entry.data.length, 0);
  if (bytesSampled === 0) {
    issues.push("No bytes available in selected executable segment(s)/section(s) for disassembly.");
    return emptyReport(0);
  }
  const seeds = await collectElfInstructionSetSeeds(file, opts, regions, sampledSections, issues);
  if (!seeds) return emptyReport(0);
  const { entrypoints, seedSummary } = seeds;

  reportProgress(opts, {
    stage: "loading",
    bytesSampled,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0
  });
  if (opts.signal?.aborted) {
    issues.push("Disassembly cancelled.");
    return emptyReport(bytesSampled, seedSummary);
  }

  let iced: unknown;
  try {
    iced = await loadIcedX86();
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return emptyReport(bytesSampled, seedSummary);
  }
  if (!isIcedX86Module(iced)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyReport(bytesSampled, seedSummary);
  }
  const decoded = await decodeElfInstructionSetUsage({
    iced,
    bitness,
    sampledSections,
    entrypoints,
    yieldEveryInstructions,
    bytesSampled,
    issues,
    opts
  });
  return {
    bitness,
    bytesSampled,
    bytesDecoded: decoded.bytesDecoded,
    instructionCount: decoded.instructionCount,
    invalidInstructionCount: decoded.invalidInstructionCount,
    instructionSets: decoded.instructionSets,
    issues,
    seedSummary
  };
}

const decodeElfInstructionSetUsage = async (
  run: ElfInstructionSetDecodeRun
): Promise<ElfInstructionSetDecodeResult> => {
  const instructionSetUsage = createX86InstructionSetUsageTracker(run.iced.CpuidFeature);
  let bytesDecoded = 0;
  let instructionCount = 0;
  let invalidInstructionCount = 0;
  const reportDecodingProgress = (): void => {
    reportProgress(run.opts, {
      stage: "decoding",
      bytesSampled: run.bytesSampled,
      bytesDecoded,
      instructionCount,
      invalidInstructionCount,
      knownFeatureCounts: instructionSetUsage.knownFeatureCounts()
    });
  };
  reportDecodingProgress();
  try {
    const result = await disassembleControlFlowForInstructionSetsVaddr({
      iced: run.iced,
      bitness: run.bitness,
      sections: run.sampledSections.map(entry => ({ vaddrStart: entry.vaddrStart, data: entry.data })),
      entrypoints: run.entrypoints,
      yieldEveryInstructions: run.yieldEveryInstructions,
      featureCounts: instructionSetUsage.featureCounts,
      issues: run.issues,
      ...(run.opts.signal ? { signal: run.opts.signal } : {}),
      onYield: async snapshot => {
        bytesDecoded = snapshot.bytesDecoded;
        instructionCount = snapshot.instructionCount;
        invalidInstructionCount = snapshot.invalidInstructionCount;
        reportDecodingProgress();
        await yieldToEventLoop();
      }
    });
    bytesDecoded = result.bytesDecoded;
    instructionCount = result.instructionCount;
    invalidInstructionCount = result.invalidInstructionCount;
  } catch (err) {
    run.issues.push(`Disassembly failed (${String(err)})`);
  }
  reportProgress(run.opts, {
    stage: "done",
    bytesSampled: run.bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: instructionSetUsage.knownFeatureCounts()
  });
  return {
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    instructionSets: instructionSetUsage.instructionSets()
  };
};
