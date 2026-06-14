"use strict";

import type {
  AnalyzeElfInstructionSetOptions,
  ElfDisassemblySeedSourceStats,
  ElfDisassemblySeedSummary
} from "./disassembly-types.js";
import { collectElfDisassemblySeedGroups } from "./disassembly-seeds.js";
import {
  findElfRegionContainingVaddr,
  type ElfExecutableRegion
} from "./executable-regions.js";
import type { ElfSampledSection } from "./disassembly-sampling.js";

type ElfSeedAddResult = "added" | "duplicate" | "notExecutable" | "zero";

export type ElfInstructionSetSeeds = {
  entrypoints: bigint[];
  seedSummary: ElfDisassemblySeedSummary;
};

export const collectElfInstructionSetSeeds = async (
  file: File,
  opts: AnalyzeElfInstructionSetOptions,
  regions: ElfExecutableRegion[],
  sampledSections: ElfSampledSection[],
  issues: string[]
): Promise<ElfInstructionSetSeeds | null> => {
  const requestedEntrypointVaddr = typeof opts.entrypointVaddr === "bigint" ? opts.entrypointVaddr : 0n;
  const seedSources: ElfDisassemblySeedSourceStats[] = [];
  let fallbackSource: string | null = null;
  const entrypoints: bigint[] = [];
  const entrypointsSet = new Set<bigint>();
  const addSeedVaddr = (vaddr: bigint): ElfSeedAddResult =>
    addExecutableSeedVaddr(regions, entrypoints, entrypointsSet, vaddr);
  addElfHeaderEntrypoint(requestedEntrypointVaddr, addSeedVaddr, seedSources, issues);
  for (const group of await collectElfDisassemblySeedGroups({
    file,
    programHeaders: opts.programHeaders,
    sections: opts.sections,
    is64: opts.is64Bit,
    littleEndian: opts.littleEndian,
    issues
  })) {
    const stats = addElfSeedGroup(group.source, group.vaddrs, addSeedVaddr);
    if (stats.skippedNotExecutable > 0) {
      issues.push(`Skipped ${stats.skippedNotExecutable} seed(s) from ${group.source} outside executable ranges.`);
    }
    if (stats.candidates > 0) seedSources.push(stats);
  }
  if (entrypoints.length === 0) {
    const fallback = sampledSections[0];
    if (!fallback) return null;
    fallbackSource = fallback.label;
    addSeedVaddr(fallback.vaddrStart);
    issues.push(`Falling back to ${fallback.label} for disassembly sample.`);
  }
  return {
    entrypoints,
    seedSummary: {
      entrypointVaddr: requestedEntrypointVaddr,
      uniqueEntrypoints: entrypoints.length,
      fallbackSource,
      sources: seedSources
    }
  };
};

export const addExecutableSeedVaddr = (
  regions: ElfExecutableRegion[],
  entrypoints: bigint[],
  entrypointsSet: Set<bigint>,
  vaddr: bigint
): ElfSeedAddResult => {
  if (vaddr === 0n) return "zero";
  if (findElfRegionContainingVaddr(regions, vaddr) == null) return "notExecutable";
  const normalized = BigInt.asUintN(64, vaddr);
  if (entrypointsSet.has(normalized)) return "duplicate";
  entrypointsSet.add(normalized);
  entrypoints.push(normalized);
  return "added";
};

const addElfHeaderEntrypoint = (
  requestedEntrypointVaddr: bigint,
  addSeedVaddr: (vaddr: bigint) => ElfSeedAddResult,
  seedSources: ElfDisassemblySeedSourceStats[],
  issues: string[]
): void => {
  if (requestedEntrypointVaddr === 0n) return;
  const stats: ElfDisassemblySeedSourceStats = createSeedStats("ELF header entry point");
  const result = addSeedVaddr(requestedEntrypointVaddr);
  if (result === "added") stats.added += 1;
  else if (result === "duplicate") stats.skippedDuplicate += 1;
  else if (result === "notExecutable") {
    stats.skippedNotExecutable += 1;
    issues.push(`Entry point 0x${requestedEntrypointVaddr.toString(16)} does not map into an executable segment/section.`);
  }
  seedSources.push(stats);
};

const addElfSeedGroup = (
  source: string,
  vaddrs: bigint[],
  addSeedVaddr: (vaddr: bigint) => ElfSeedAddResult
): ElfDisassemblySeedSourceStats => {
  const stats = createSeedStats(source);
  for (const vaddr of vaddrs) {
    stats.candidates += 1;
    const result = addSeedVaddr(vaddr);
    if (result === "added") stats.added += 1;
    else if (result === "duplicate") stats.skippedDuplicate += 1;
    else if (result === "zero") stats.skippedZero += 1;
    else stats.skippedNotExecutable += 1;
  }
  return stats;
};

const createSeedStats = (source: string): ElfDisassemblySeedSourceStats => ({
  source,
  candidates: 0,
  added: 0,
  skippedZero: 0,
  skippedNotExecutable: 0,
  skippedDuplicate: 0
});
