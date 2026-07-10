"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import {
  prepareDwarfSectionSources,
  type DwarfSectionCandidate
} from "../dwarf/compressed-sections.js";
import { analyzeDwarfSources } from "../dwarf/index.js";
import type { DwarfAnalysis } from "../dwarf/types.js";
import type { ElfSectionHeader } from "./types.js";

// ELF gABI section flag SHF_COMPRESSED:
// https://www.sco.com/developers/gabi/latest/ch4.sheader.html
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
  elfClass: "elf32" | "elf64",
  byteOrder: "big" | "little",
  issues: string[]
): DwarfSectionCandidate | null => {
  const name = section.name ?? "";
  if (!isDwarfSectionName(name)) return null;
  const offset = safeNumber(section.offset, `${name} offset`, issues);
  const size = safeNumber(section.size, `${name} size`, issues);
  if (offset == null || size == null) return null;
  const gnuCompressed = name.startsWith(".zdebug_");
  const elfCompressed = (section.flags & SHF_COMPRESSED) !== 0n;
  return {
    section: {
      name,
      offset,
      size,
      compressed: gnuCompressed || elfCompressed,
      ...(relocationTargetName(name) != null || relocationTargets.has(name)
        ? { requiresRelocations: true }
        : {})
    },
    compression: gnuCompressed
      ? { kind: "gnu-zlib" }
      : elfCompressed
        ? { kind: "elf", elfClass, byteOrder }
        : null
  };
};

export const analyzeElfDwarf = async (
  file: File,
  sections: ElfSectionHeader[],
  elfClass: "elf32" | "elf64",
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfAnalysis | null> => {
  const relocationTargets = new Set(
    sections
      .map(section => relocationTargetName(section.name ?? ""))
      .filter((name): name is string => name != null)
  );
  const dwarfSections = sections
    .map(section => toDwarfSection(
      section,
      relocationTargets,
      elfClass,
      littleEndian ? "little" : "big",
      issues
    ))
    .filter((section): section is DwarfSectionCandidate => section != null);
  if (!dwarfSections.length) return null;
  const prepared = await prepareDwarfSectionSources(
    createFileRangeReader(file, 0, file.size),
    dwarfSections
  );
  const dwarf = await analyzeDwarfSources(
    prepared.sources,
    littleEndian ? "little" : "big"
  );
  return { ...dwarf, issues: [...prepared.issues, ...dwarf.issues] };
};
