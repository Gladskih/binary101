"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_SECTION } from "./constants.js";
import { parseAbbreviationTable } from "./abbreviations.js";
import { parseDwarfDies } from "./dies.js";
import { parseDwarfLines } from "./lines.js";
import type {
  DwarfAbbreviation,
  DwarfAnalysis,
  DwarfSectionInput,
  DwarfSectionSource,
  DwarfSectionStatus,
  DwarfUnit
} from "./types.js";
import { parseDwarfUnitHeader } from "./unit-header.js";

const decodedSectionNames = new Set<string>([
  DWARF_SECTION.information,
  DWARF_SECTION.lines,
  DWARF_SECTION.types,
  DWARF_SECTION.abbreviations
]);
const referencedSectionNames = new Set<string>([
  DWARF_SECTION.strings,
  DWARF_SECTION.lineStrings,
  DWARF_SECTION.stringOffsets
]);

const supportedSectionName = (name: string): boolean =>
  decodedSectionNames.has(name) || referencedSectionNames.has(name);

const sectionStatus = (source: DwarfSectionSource): DwarfSectionStatus => {
  if (source.summary.requiresRelocations) return "relocations-unsupported";
  if (!source.decoded && source.summary.compressed && supportedSectionName(source.section.name)) {
    return "compressed-unsupported";
  }
  if (decodedSectionNames.has(source.section.name)) return "decoded";
  if (referencedSectionNames.has(source.section.name)) return "referenced";
  return "inventory-only";
};

const normalizeSource = (
  source: DwarfSectionSource,
  issues: string[]
): DwarfSectionSource => {
  const { reader, section } = source;
  if (!Number.isSafeInteger(section.offset) || !Number.isSafeInteger(section.size) ||
      section.offset < 0 || section.size < 0) {
    issues.push(`${section.name}: section file range is not a safe non-negative integer range.`);
    return { ...source, section: { ...section, offset: 0, size: 0 }, decoded: false };
  }
  const readableSize = section.offset < reader.size
    ? Math.min(section.size, reader.size - section.offset)
    : 0;
  if (readableSize !== section.size) {
    issues.push(
      `${section.name}: section data is truncated (${readableSize} of ${section.size} bytes readable).`
    );
  }
  return { ...source, section: { ...section, size: readableSize } };
};

const buildSectionMap = (
  sources: DwarfSectionSource[],
  issues: string[]
): Map<string, DwarfSectionSource> => {
  const byName = new Map<string, DwarfSectionSource>();
  for (const source of sources) {
    if (byName.has(source.section.name)) {
      issues.push(`${source.section.name}: duplicate DWARF section; the first section is used.`);
    } else if (source.decoded && !source.summary.requiresRelocations) {
      byName.set(source.section.name, source);
    }
  }
  return byName;
};

const parseInfoSection = async (
  source: DwarfSectionSource,
  sections: Map<string, DwarfSectionSource>,
  littleEndian: boolean,
  issues: string[],
  abbreviationCache: Map<string, Map<bigint, DwarfAbbreviation>>
): Promise<DwarfUnit[]> => {
  const abbreviationSource = sections.get(DWARF_SECTION.abbreviations);
  if (!abbreviationSource) {
    issues.push(
      `${source.section.name}: ${DWARF_SECTION.abbreviations} is required to decode units.`
    );
    return [];
  }
  const units: DwarfUnit[] = [];
  let offset = 0;
  while (offset < source.section.size) {
    const header = await parseDwarfUnitHeader(
      source.reader,
      source.section,
      offset,
      littleEndian,
      issues
    );
    if (!header) break;
    const cacheKey = header.abbreviationOffset.toString();
    let abbreviations = abbreviationCache.get(cacheKey);
    if (!abbreviations) {
      const parsed = await parseAbbreviationTable(
        abbreviationSource.reader,
        abbreviationSource.section,
        header.abbreviationOffset,
        littleEndian,
        issues
      );
      if (!parsed) break;
      abbreviations = parsed;
      abbreviationCache.set(cacheKey, parsed);
    }
    const dies = await parseDwarfDies(
      source.reader,
      source.section,
      sections,
      header,
      abbreviations,
      littleEndian,
      issues
    );
    units.push({
      sectionName: source.section.name,
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

export const analyzeDwarfSources = async (
  inputSources: DwarfSectionSource[],
  byteOrder: "big" | "little"
): Promise<DwarfAnalysis> => {
  const issues: string[] = [];
  const littleEndian = byteOrder === "little";
  const sections = inputSources.map(source => ({
    ...source.summary,
    status: sectionStatus(source)
  }));
  inputSources.filter(source =>
    source.summary.compressed && !source.decoded && supportedSectionName(source.section.name)
  ).forEach(source => {
    issues.push(
      `Compressed DWARF section ${source.summary.name} is inventoried but not decoded.`
    );
  });
  const relocationSections = inputSources.filter(source => source.summary.requiresRelocations);
  if (relocationSections.length) {
    issues.push(
      `ELF relocations are required but are not applied in this iteration: ` +
      `${relocationSections.map(source => source.summary.name).join(", ")}.`
    );
  }
  const normalizedSources = inputSources.map(source => normalizeSource(source, issues));
  const sectionMap = buildSectionMap(normalizedSources, issues);
  const infoSections = [
    sectionMap.get(DWARF_SECTION.information),
    sectionMap.get(DWARF_SECTION.types)
  ]
    .filter((source): source is DwarfSectionSource =>
      source != null && source.section.size > 0);
  const abbreviationCache = new Map<string, Map<bigint, DwarfAbbreviation>>();
  const units: DwarfUnit[] = [];
  for (const source of infoSections) {
    units.push(...await parseInfoSection(
      source,
      sectionMap,
      littleEndian,
      issues,
      abbreviationCache
    ));
  }
  const lineSource = sectionMap.get(DWARF_SECTION.lines);
  const linePrograms = lineSource && lineSource.section.size > 0
    ? await parseDwarfLines(lineSource, sectionMap, littleEndian, issues)
    : [];
  return { sections, units, linePrograms, issues };
};

export const analyzeDwarf = async (
  reader: FileRangeReader,
  inputSections: DwarfSectionInput[],
  littleEndian: boolean
): Promise<DwarfAnalysis> => analyzeDwarfSources(inputSections.map(section => ({
  summary: section,
  section,
  reader,
  decoded: !section.compressed && !section.requiresRelocations
})), littleEndian ? "little" : "big");
