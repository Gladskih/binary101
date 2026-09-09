import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import type { ElfSymbolVersions } from "./version-types.js";
import type { ElfVersionTable } from "./version-reader.js";
import { locateElfVersionTable, readVersionBytes } from "./version-reader.js";
import { readElfVersionDefinitions, readElfVersionRequirements } from "./version-records.js";

const readSymbolIndices = async (
  reader: FileRangeReader, table: ElfVersionTable, little: boolean, issues: string[]
): Promise<number[]> => {
  const symbols: number[] = [];
  // LSB 10.7.2: one Elf*_Half per dynamic symbol. Limit bounds output memory.
  const count = Math.min(table.count, Math.floor(table.size / 2), 1000000);
  if (count !== table.count || table.size % 2) {
    issues.push("Symbol version table is truncated, misaligned or exceeds the 1000000 entry limit.");
  }
  for (let index = 0; index < count; index += 1) {
    const view = await readVersionBytes(reader, table, index * 2, 2, issues);
    if (!view) break;
    symbols.push(view.getUint16(0, little));
  }
  return symbols;
};

export const parseElfSymbolVersions = async (
  file: File, elf: ElfParseResult, entries: ElfDynamicEntry[], symbolCount: number
): Promise<ElfSymbolVersions | null> => {
  const issues: string[] = [];
  const definitions = locateElfVersionTable(elf, entries, "definitions", symbolCount, issues);
  const requirements = locateElfVersionTable(elf, entries, "requirements", symbolCount, issues);
  const symbols = locateElfVersionTable(elf, entries, "symbols", symbolCount, issues);
  if (!definitions && !requirements && !symbols && !issues.length) return null;
  const reader = createFileRangeReader(file, 0, file.size);
  return {
    definitions: definitions
      ? await readElfVersionDefinitions(reader, definitions, elf.littleEndian, issues) : [],
    requirements: requirements
      ? await readElfVersionRequirements(reader, requirements, elf.littleEndian, issues) : [],
    symbols: symbols ? await readSymbolIndices(reader, symbols, elf.littleEndian, issues) : [],
    issues
  };
};
