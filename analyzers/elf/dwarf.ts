"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import { analyzeDwarf } from "../dwarf/index.js";
import type { DwarfAnalysis, DwarfSectionInput } from "../dwarf/types.js";
import type { ElfSectionHeader } from "./types.js";

// ELF gABI SHF_COMPRESSED flag, also used by GNU binutils for gABI compression:
// https://sourceware.org/binutils/docs/binutils/readelf.html
const SHF_COMPRESSED = 0x800n;

const isDwarfSectionName = (name: string): boolean =>
  name.startsWith(".debug_") || name.startsWith(".zdebug_") ||
  name.startsWith(".rel.debug_") || name.startsWith(".rela.debug_");

const relocationTargetName = (name: string): string | null => {
  if (name.startsWith(".rela.debug_")) return name.slice(".rela".length);
  if (name.startsWith(".rel.debug_")) return name.slice(".rel".length);
  return null;
};

const safeNumber = (value: bigint, label: string, issues: string[]): number | null => {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    issues.push(`${label} ${value.toString()} is too large to index into the file.`);
    return null;
  }
  return number;
};

const toDwarfSection = (
  section: ElfSectionHeader,
  relocationTargets: Set<string>,
  issues: string[]
): DwarfSectionInput | null => {
  const name = section.name ?? "";
  if (!isDwarfSectionName(name)) return null;
  const offset = safeNumber(section.offset, `${name} offset`, issues);
  const size = safeNumber(section.size, `${name} size`, issues);
  if (offset == null || size == null) return null;
  return {
    name,
    offset,
    size,
    compressed: name.startsWith(".zdebug_") || (section.flags & SHF_COMPRESSED) !== 0n,
    ...(relocationTargetName(name) != null || relocationTargets.has(name)
      ? { requiresRelocations: true }
      : {})
  };
};

export const analyzeElfDwarf = async (
  file: File,
  sections: ElfSectionHeader[],
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfAnalysis | null> => {
  const relocationTargets = new Set(
    sections
      .map(section => relocationTargetName(section.name ?? ""))
      .filter((name): name is string => name != null)
  );
  const dwarfSections = sections
    .map(section => toDwarfSection(section, relocationTargets, issues))
    .filter((section): section is DwarfSectionInput => section != null);
  return dwarfSections.length
    ? analyzeDwarf(createFileRangeReader(file, 0, file.size), dwarfSections, littleEndian)
    : null;
};
