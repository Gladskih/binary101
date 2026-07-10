"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { analyzeDwarf } from "../dwarf/index.js";
import type { DwarfAnalysis, DwarfSectionInput } from "../dwarf/types.js";
import { peSectionNameValue } from "./sections/name.js";
import type { PeSection } from "./types.js";

const isDwarfSectionName = (name: string): boolean =>
  name.startsWith(".debug_") || name.startsWith(".zdebug_");

const toDwarfSection = (section: PeSection): DwarfSectionInput | null => {
  const name = peSectionNameValue(section.name);
  if (!isDwarfSectionName(name)) return null;
  const rawSize = section.sizeOfRawData >>> 0;
  const virtualSize = section.virtualSize >>> 0;
  return {
    name,
    offset: section.pointerToRawData >>> 0,
    size: Math.min(rawSize, virtualSize || rawSize),
    compressed: name.startsWith(".zdebug_")
  };
};

export const analyzePeDwarf = async (
  reader: FileRangeReader,
  sections: PeSection[]
): Promise<DwarfAnalysis | null> => {
  const dwarfSections = sections
    .map(toDwarfSection)
    .filter((section): section is DwarfSectionInput => section != null);
  return dwarfSections.length ? analyzeDwarf(reader, dwarfSections, true) : null;
};
