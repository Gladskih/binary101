"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  prepareDwarfSectionSources,
  type DwarfSectionCandidate
} from "../dwarf/compressed-sections.js";
import { analyzeDwarfSources } from "../dwarf/index.js";
import type { DwarfAnalysis } from "../dwarf/types.js";
import { peSectionNameValue } from "./sections/name.js";
import type { PeSection } from "./types.js";

const isDwarfSectionName = (name: string): boolean =>
  name.startsWith(".debug_") || name.startsWith(".zdebug_");

const toDwarfSection = (section: PeSection): DwarfSectionCandidate | null => {
  const name = peSectionNameValue(section.name);
  if (!isDwarfSectionName(name)) return null;
  const rawSize = section.sizeOfRawData >>> 0;
  const virtualSize = section.virtualSize >>> 0;
  const compressed = name.startsWith(".zdebug_");
  return {
    section: {
      name,
      offset: section.pointerToRawData >>> 0,
      size: Math.min(rawSize, virtualSize || rawSize),
      compressed
    },
    compression: compressed ? { kind: "gnu-zlib" } : null
  };
};

export const analyzePeDwarf = async (
  reader: FileRangeReader,
  sections: PeSection[]
): Promise<DwarfAnalysis | null> => {
  const dwarfSections = sections
    .map(toDwarfSection)
    .filter((section): section is DwarfSectionCandidate => section != null);
  if (!dwarfSections.length) return null;
  const prepared = await prepareDwarfSectionSources(reader, dwarfSections);
  const dwarf = await analyzeDwarfSources(prepared.sources, "little");
  return { ...dwarf, issues: [...prepared.issues, ...dwarf.issues] };
};
