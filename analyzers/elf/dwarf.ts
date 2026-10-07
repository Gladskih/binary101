"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import {
  prepareDwarfSectionSources,
  type DwarfSectionCandidate
} from "../dwarf/compressed-sections.js";
import { analyzeDwarfSources } from "../dwarf/index.js";
import type { DwarfSectionSource } from "../dwarf/types.js";
import type { DwarfAnalysis } from "../dwarf/types.js";
import type { ElfSectionHeader } from "./types.js";
import { ELF_SECTION_TYPE } from "./abi-constants.js";
import { applyElfDwarfRelocations } from "./dwarf-relocations.js";
import type { ElfRelocationImage, ElfRelocationInfo } from "./relocation-types.js";

// ELF gABI section flag SHF_COMPRESSED:
// https://www.sco.com/developers/gabi/latest/ch4.sheader.html
const SHF_COMPRESSED = 0x800n;

const isDwarfSectionName = (name: string): boolean =>
  name === ".gnu_debugaltlink" || name.startsWith(".debug_") || name.startsWith(".zdebug_") ||
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
      ...(relocationTargets.has(name)
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

const collectDwarfSections = (sections: ElfSectionHeader[], elfClass: "elf32" | "elf64",
  byteOrder: "little" | "big", issues: string[]): DwarfSectionCandidate[] => {
  const relocationTargets = new Set(
    sections
      .map(section => relocationTargetName(section.name ?? ""))
      .filter((name): name is string => name != null)
  );
  // gABI sh_info identifies targets independently of relocation section names.
  for (const section of sections) {
    if (section.type !== ELF_SECTION_TYPE.RELA && section.type !== ELF_SECTION_TYPE.REL) continue;
    const target = sections.find(item => item.index === section.info);
    if (target?.name) relocationTargets.add(target.name);
  }
  return sections
    .map(section => toDwarfSection(
      section,
      relocationTargets,
      elfClass,
      byteOrder,
      issues
    ))
    .filter((section): section is DwarfSectionCandidate => section != null);
};

export type ElfDwarfSources = { sources: DwarfSectionSource[]; issues: string[] };

export const prepareElfDwarfSources = async (file: File, sections: ElfSectionHeader[],
  elfClass: "elf32" | "elf64", littleEndian: boolean, issues: string[]): Promise<ElfDwarfSources | null> => {
  const candidates = collectDwarfSections(sections, elfClass, littleEndian ? "little" : "big", issues);
  if (!candidates.length) return null;
  const prepared = await prepareDwarfSectionSources(createFileRangeReader(file, 0, file.size),
    candidates.map(candidate => ({ ...candidate, section: { ...candidate.section, requiresRelocations: false } })));
  return { sources: prepared.sources.map((source, index) => ({ ...source, summary: candidates[index]!.section })),
    issues: prepared.issues };
};

export const elfDwarfLogicalSizes = (sections: ElfSectionHeader[],
  prepared: ElfDwarfSources | null): Map<number, bigint> => {
  const sizes = new Map<number, bigint>();
  for (const section of sections) {
    const source = prepared?.sources.find(source => source.summary.name === section.name &&
      BigInt(source.summary.offset) === section.offset);
    if (source?.decoded && source.summary.compressed) sizes.set(section.index, BigInt(source.section.size));
  }
  return sizes;
};

const relocatedDwarfSources = async (prepared: ElfDwarfSources,
  elf: ElfRelocationImage | undefined, relocations: ElfRelocationInfo | undefined): Promise<DwarfSectionSource[]> =>
  elf && relocations ? applyElfDwarfRelocations(prepared.sources, elf, relocations, prepared.issues) : prepared.sources;

export const analyzeElfDwarf = async (file: File, sections: ElfSectionHeader[],
  elfClass: "elf32" | "elf64", littleEndian: boolean, issues: string[],
  elf?: ElfRelocationImage, relocations?: ElfRelocationInfo,
  preparedSources?: ElfDwarfSources): Promise<DwarfAnalysis | null> => {
  const prepared = preparedSources ?? await prepareElfDwarfSources(file, sections, elfClass, littleEndian, issues);
  if (!prepared) return null;
  const dwarf = await analyzeDwarfSources(await relocatedDwarfSources(prepared, elf, relocations),
    littleEndian ? "little" : "big", elfClass === "elf64" ? 8 : 4, elf?.header.machine ?? 0);
  return { ...dwarf, issues: [...prepared.issues, ...dwarf.issues] };
};
