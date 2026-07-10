"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_SECTION } from "./constants.js";
import { parseAbbreviationTable } from "./abbreviations.js";
import { parseDwarfDies } from "./dies.js";
import type {
  DwarfAbbreviation,
  DwarfAnalysis,
  DwarfSectionInput,
  DwarfSectionStatus,
  DwarfUnit
} from "./types.js";
import { parseDwarfUnitHeader } from "./unit-header.js";

const decodedSectionNames = new Set<string>([
  DWARF_SECTION.information,
  DWARF_SECTION.types,
  DWARF_SECTION.abbreviations
]);
const referencedSectionNames = new Set<string>([
  DWARF_SECTION.strings,
  DWARF_SECTION.lineStrings,
  DWARF_SECTION.stringOffsets
]);

const sectionStatus = (section: DwarfSectionInput): DwarfSectionStatus => {
  if (section.compressed) return "compressed-unsupported";
  if (section.requiresRelocations) return "relocations-unsupported";
  if (decodedSectionNames.has(section.name)) return "decoded";
  if (referencedSectionNames.has(section.name)) return "referenced";
  return "inventory-only";
};

const normalizeSection = (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  issues: string[]
): DwarfSectionInput => {
  if (!Number.isSafeInteger(section.offset) || !Number.isSafeInteger(section.size) ||
      section.offset < 0 || section.size < 0) {
    issues.push(`${section.name}: section file range is not a safe non-negative integer range.`);
    return { ...section, offset: 0, size: 0 };
  }
  const readableSize = section.offset < reader.size
    ? Math.min(section.size, reader.size - section.offset)
    : 0;
  if (readableSize !== section.size) {
    issues.push(
      `${section.name}: section data is truncated (${readableSize} of ${section.size} bytes readable).`
    );
  }
  return { ...section, size: readableSize };
};

const buildSectionMap = (
  sections: DwarfSectionInput[],
  issues: string[]
): Map<string, DwarfSectionInput> => {
  const byName = new Map<string, DwarfSectionInput>();
  for (const section of sections) {
    if (byName.has(section.name)) {
      issues.push(`${section.name}: duplicate DWARF section; the first section is used.`);
    } else if (!section.compressed && !section.requiresRelocations) {
      byName.set(section.name, section);
    }
  }
  return byName;
};

const parseInfoSection = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  sections: Map<string, DwarfSectionInput>,
  littleEndian: boolean,
  issues: string[],
  abbreviationCache: Map<string, Map<bigint, DwarfAbbreviation>>
): Promise<DwarfUnit[]> => {
  const abbreviationSection = sections.get(DWARF_SECTION.abbreviations);
  if (!abbreviationSection) {
    issues.push(`${section.name}: ${DWARF_SECTION.abbreviations} is required to decode units.`);
    return [];
  }
  const units: DwarfUnit[] = [];
  let offset = 0;
  while (offset < section.size) {
    const header = await parseDwarfUnitHeader(reader, section, offset, littleEndian, issues);
    if (!header) break;
    const cacheKey = header.abbreviationOffset.toString();
    let abbreviations = abbreviationCache.get(cacheKey);
    if (!abbreviations) {
      const parsed = await parseAbbreviationTable(
        reader,
        abbreviationSection,
        header.abbreviationOffset,
        littleEndian,
        issues
      );
      if (!parsed) break;
      abbreviations = parsed;
      abbreviationCache.set(cacheKey, parsed);
    }
    const dies = await parseDwarfDies(
      reader,
      section,
      sections,
      header,
      abbreviations,
      littleEndian,
      issues
    );
    units.push({
      sectionName: section.name,
      offset: header.offset,
      length: header.length,
      format: header.format,
      version: header.version,
      unitType: header.unitType,
      addressSize: header.addressSize,
      abbreviationOffset: header.abbreviationOffset,
      root: dies.root,
      tagCounts: dies.tagCounts,
      maxDepth: dies.maxDepth
    });
    if (header.end <= offset) break;
    offset = header.end;
  }
  return units;
};

export const analyzeDwarf = async (
  reader: FileRangeReader,
  inputSections: DwarfSectionInput[],
  littleEndian: boolean
): Promise<DwarfAnalysis> => {
  const issues: string[] = [];
  const sections = inputSections.map(section => ({ ...section, status: sectionStatus(section) }));
  inputSections.filter(section => section.compressed).forEach(section => {
    issues.push(`Compressed DWARF section ${section.name} is inventoried but not decoded.`);
  });
  const relocationSections = inputSections.filter(section => section.requiresRelocations);
  if (relocationSections.length) {
    issues.push(
      `ELF relocations are required but are not applied in this iteration: ` +
      `${relocationSections.map(section => section.name).join(", ")}.`
    );
  }
  const normalizedSections = inputSections.map(section => normalizeSection(reader, section, issues));
  const sectionMap = buildSectionMap(normalizedSections, issues);
  const infoSections = [
    sectionMap.get(DWARF_SECTION.information),
    sectionMap.get(DWARF_SECTION.types)
  ]
    .filter((section): section is DwarfSectionInput => section != null && section.size > 0);
  const abbreviationCache = new Map<string, Map<bigint, DwarfAbbreviation>>();
  const units: DwarfUnit[] = [];
  for (const section of infoSections) {
    units.push(...await parseInfoSection(
      reader,
      section,
      sectionMap,
      littleEndian,
      issues,
      abbreviationCache
    ));
  }
  return { sections, units, issues };
};
