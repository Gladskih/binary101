"use strict";

import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "../x86/cpuid-features.js";
import type {
  AnalyzeElfInstructionSetOptions,
  ElfDisassemblySeedSourceStats,
  ElfDisassemblySeedSummary,
  ElfInstructionSetProgress,
  ElfInstructionSetReport
} from "./disassembly-types.js";
import { findElfRegionContainingVaddr, getElfExecutableRegions } from "./executable-regions.js";
import { collectElfDisassemblySeedGroups } from "./disassembly-seeds.js";
import { disassembleControlFlowForInstructionSetsVaddr } from "../x86/disassembly-control-flow-vaddr.js";
import { isIcedX86Module } from "../x86/disassembly-iced.js";

const ELF_MACHINE_I386 = 3;
const ELF_MACHINE_X86_64 = 62;

type SampledSection = { vaddrStart: bigint; data: Uint8Array<ArrayBuffer>; label: string };

const reportProgress = (opts: AnalyzeElfInstructionSetOptions, progress: ElfInstructionSetProgress): void => {
  if (!opts.onProgress) return;
  try {
    opts.onProgress(progress);
  } catch {
    // Progress callbacks are UI-facing; analysis should continue even if a consumer throws.
  }
};

const yieldToEventLoop = async (): Promise<void> => new Promise<void>(resolve => setTimeout(resolve, 0));

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

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
  const sampledSections = (
    await Promise.all(
      regions.map(async region => {
        const start = toSafeIndex(region.fileOffset, `${region.label} file offset`, issues);
        const size = toSafeIndex(region.fileSize, `${region.label} file size`, issues);
        if (start == null || size == null || size <= 0) return null;
        const end = Math.min(file.size, start + size);
        if (start >= file.size || end <= start) return null;
        if (end !== start + size) {
          issues.push(`${region.label} extends past end of file; truncating to available bytes.`);
        }
        return {
          vaddrStart: region.vaddr,
          data: new Uint8Array(await file.slice(start, end).arrayBuffer()),
          label: region.label
        };
      })
    )
  ).filter((entry): entry is SampledSection => entry != null && entry.data.length > 0);
  const bytesSampled = sampledSections.reduce((sum, entry) => sum + entry.data.length, 0);
  if (bytesSampled === 0) {
    issues.push("No bytes available in selected executable segment(s)/section(s) for disassembly.");
    return emptyReport(0);
  }
  const requestedEntrypointVaddr = typeof opts.entrypointVaddr === "bigint" ? opts.entrypointVaddr : 0n;
  const seedSources: ElfDisassemblySeedSourceStats[] = [];
  let fallbackSource: string | null = null;
  const entrypoints: bigint[] = [];
  const entrypointsSet = new Set<bigint>();
  const isExecutableSeed = (vaddr: bigint): boolean => findElfRegionContainingVaddr(regions, vaddr) != null;
  const addSeedVaddr = (vaddr: bigint): "added" | "duplicate" | "notExecutable" | "zero" => {
    if (vaddr === 0n) return "zero";
    if (!isExecutableSeed(vaddr)) return "notExecutable";
    const normalized = BigInt.asUintN(64, vaddr);
    if (entrypointsSet.has(normalized)) return "duplicate";
    entrypointsSet.add(normalized);
    entrypoints.push(normalized);
    return "added";
  };
  if (requestedEntrypointVaddr !== 0n) {
    const source = `Entry point 0x${requestedEntrypointVaddr.toString(16)}`;
    const entryStats: ElfDisassemblySeedSourceStats = {
      source: "ELF header entry point",
      candidates: 1,
      added: 0,
      skippedZero: 0,
      skippedNotExecutable: 0,
      skippedDuplicate: 0
    };
    const result = addSeedVaddr(requestedEntrypointVaddr);
    if (result === "added") entryStats.added += 1;
    else if (result === "duplicate") entryStats.skippedDuplicate += 1;
    else if (result === "notExecutable") {
      entryStats.skippedNotExecutable += 1;
      issues.push(`${source} does not map into an executable segment/section.`);
    }
    seedSources.push(entryStats);
  }

  const seedGroups = await collectElfDisassemblySeedGroups({
    file,
    programHeaders: opts.programHeaders,
    sections: opts.sections,
    is64: opts.is64Bit,
    littleEndian: opts.littleEndian,
    issues
  });
  for (const group of seedGroups) {
    const stats: ElfDisassemblySeedSourceStats = {
      source: group.source,
      candidates: 0,
      added: 0,
      skippedZero: 0,
      skippedNotExecutable: 0,
      skippedDuplicate: 0
    };
    for (const vaddr of group.vaddrs) {
      stats.candidates += 1;
      const result = addSeedVaddr(vaddr);
      if (result === "added") stats.added += 1;
      else if (result === "duplicate") stats.skippedDuplicate += 1;
      else if (result === "zero") stats.skippedZero += 1;
      else stats.skippedNotExecutable += 1;
    }
    if (stats.skippedNotExecutable > 0) {
      issues.push(`Skipped ${stats.skippedNotExecutable} seed(s) from ${group.source} outside executable ranges.`);
    }
    if (stats.candidates > 0) seedSources.push(stats);
  }

  if (entrypoints.length === 0) {
    const fallback = sampledSections[0];
    if (!fallback) return emptyReport(0);
    fallbackSource = fallback.label;
    addSeedVaddr(fallback.vaddrStart);
    issues.push(`Falling back to ${fallback.label} for disassembly sample.`);
  }

  const seedSummary: ElfDisassemblySeedSummary = {
    entrypointVaddr: requestedEntrypointVaddr,
    uniqueEntrypoints: entrypoints.length,
    fallbackSource,
    sources: seedSources
  };

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
    iced = await import("iced-x86");
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return emptyReport(bytesSampled, seedSummary);
  }
  if (!isIcedX86Module(iced)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyReport(bytesSampled, seedSummary);
  }

  const featureCounts = new Map<number, number>();
  const knownFeatures = KNOWN_CPUID_FEATURES
    .map(id => ({ id, value: iced.CpuidFeature[id] }))
    .filter((entry): entry is { id: string; value: number } => typeof entry.value === "number");
  const getKnownFeatureCounts = (): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const { id, value } of knownFeatures) {
      const count = featureCounts.get(value);
      if (count) out[id] = count;
    }
    return out;
  };

  let bytesDecoded = 0;
  let instructionCount = 0;
  let invalidInstructionCount = 0;
  const reportDecodingProgress = (): void => {
    reportProgress(opts, {
      stage: "decoding",
      bytesSampled,
      bytesDecoded,
      instructionCount,
      invalidInstructionCount,
      knownFeatureCounts: getKnownFeatureCounts()
    });
  };
  reportDecodingProgress();

  try {
    const result = await disassembleControlFlowForInstructionSetsVaddr({
      iced,
      bitness,
      sections: sampledSections.map(entry => ({ vaddrStart: entry.vaddrStart, data: entry.data })),
      entrypoints,
      yieldEveryInstructions,
      featureCounts,
      issues,
      ...(opts.signal ? { signal: opts.signal } : {}),
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
    issues.push(`Disassembly failed (${String(err)})`);
  }

  const instructionSets = [...featureCounts.entries()]
    .map(([feature, count]) => {
      const id = iced.CpuidFeature[feature] ?? `#${feature}`;
      return {
        id,
        label: formatCpuidLabel(id),
        description: describeCpuidFeature(id),
        instructionCount: count
      };
    })
    .sort((a, b) => b.instructionCount - a.instructionCount || a.id.localeCompare(b.id));

  reportProgress(opts, {
    stage: "done",
    bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: getKnownFeatureCounts()
  });

  return {
    bitness,
    bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    instructionSets,
    issues,
    seedSummary
  };
}
