import type { createCodeExclusionIndex } from "../code-exclusions.js";
import type { ElfInstructionSetSeeds } from "./disassembly-entrypoints.js";
import type { ElfDisassemblySeedSourceStats } from "./disassembly-types.js";
import type { ElfExecutableRegion } from "./executable-regions.js";
import type { ElfSymbolTable } from "./symbol-tables.js";
import { elfSymbolSectionReference } from "./symbol-section-index.js";

export const collectElfObjectCodeSeeds = (
  tables: ElfSymbolTable[], regions: ElfExecutableRegion[],
  crossedData: ReturnType<typeof createCodeExclusionIndex>
): ElfInstructionSetSeeds => {
  const bySection = new Map(regions.map(region => [region.sectionIndex, region]));
  const entrypoints = new Set<bigint>();
  const anchored = new Set<ElfExecutableRegion>();
  const sources = tables.map(table => addFunctionSeeds(table, bySection, entrypoints, anchored, crossedData))
    .filter(stats => stats.candidates !== 0);
  let fallbackCount = 0;
  for (const region of regions) {
    if (anchored.has(region) || crossedData(region.vaddr, 1) != null) continue;
    entrypoints.add(region.vaddr);
    fallbackCount += 1;
  }
  return {
    entrypoints: [...entrypoints],
    seedSummary: {
      entrypointVaddr: 0n, uniqueEntrypoints: entrypoints.size, sources,
      fallbackSource: fallbackCount ? `start of ${fallbackCount} executable section(s)` : null
    }
  };
};

const addFunctionSeeds = (
  table: ElfSymbolTable, bySection: Map<number | undefined, ElfExecutableRegion>,
  entrypoints: Set<bigint>, anchored: Set<ElfExecutableRegion>,
  crossedData: ReturnType<typeof createCodeExclusionIndex>
): ElfDisassemblySeedSourceStats => {
  const stats: ElfDisassemblySeedSourceStats = {
    source: `Function symbols in section #${table.sectionIndex}`,
    candidates: 0, added: 0, skippedNotExecutable: 0, skippedZero: 0,
    skippedDuplicate: 0, skippedData: 0
  };
  for (const symbol of table.entries) {
    // gABI 3 and 5: STT_FUNC and a section-relative offset (including zero).
    // GNU STT_GNU_IFUNC is a function resolver (glibc elf.h).
    const type = symbol.info & 0x0f;
    if (type !== 2 && type !== 10) continue;
    stats.candidates += 1;
    const index = elfSymbolSectionReference(symbol.sectionIndex, symbol.rawSectionIndex);
    const region = index == null ? undefined : bySection.get(index);
    if (!region || symbol.value >= region.fileSize || symbol.value < 0n) {
      stats.skippedNotExecutable += 1;
      continue;
    }
    const offset = region.vaddr + symbol.value;
    if (crossedData(offset, 1) != null) {
      stats.skippedData = (stats.skippedData ?? 0) + 1;
      continue;
    }
    anchored.add(region);
    if (entrypoints.has(offset)) stats.skippedDuplicate += 1;
    else {
      entrypoints.add(offset);
      stats.added += 1;
    }
  }
  return stats;
};
