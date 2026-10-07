"use strict";

import { readDwarfSectionAnalysis } from "./section-analysis.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_SECTION } from "./constants.js";
import { dwarfSplitBaseName } from "./package-sections.js";
import type {
  DwarfAnalysis,
  DwarfSectionInput,
  DwarfSectionSource,
  DwarfSectionStatus
} from "./types.js";

const decodedSectionNames = new Set<string>([
  DWARF_SECTION.information,
  DWARF_SECTION.lines,
  DWARF_SECTION.types,
  DWARF_SECTION.abbreviations, ".debug_macro", ".debug_macinfo", ".debug_pubnames",
  ".debug_pubtypes", ".debug_gnu_pubnames", ".debug_gnu_pubtypes", ".debug_aranges", ".debug_names", ".debug_frame",
  ".debug_cu_index", ".debug_tu_index", ".debug_sup", ".gnu_debugaltlink"
]);
const referencedSectionNames = new Set<string>([
  DWARF_SECTION.strings,
  DWARF_SECTION.lineStrings,
  DWARF_SECTION.stringOffsets,
  ".debug_addr", ".debug_ranges", ".debug_rnglists", ".debug_loc", ".debug_loclists"
]);

const supportedSectionName = (name: string): boolean =>
  decodedSectionNames.has(dwarfSplitBaseName(name)) || referencedSectionNames.has(dwarfSplitBaseName(name));

const sectionStatus = (source: DwarfSectionSource): DwarfSectionStatus => {
  if (source.summary.requiresRelocations) return "relocations-unsupported";
  if (!source.decoded && source.summary.compressed && supportedSectionName(source.section.name)) {
    return "compressed-unsupported";
  }
  if (!source.decoded) return "unavailable";
  if (decodedSectionNames.has(dwarfSplitBaseName(source.section.name))) return "decoded";
  if (referencedSectionNames.has(dwarfSplitBaseName(source.section.name))) return "referenced";
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

export const analyzeDwarfSources = async (
  inputSources: DwarfSectionSource[],
  byteOrder: "big" | "little", addressSize = 0, machine = 0
): Promise<DwarfAnalysis> => {
  const issues: string[] = [];
  const normalizedSources = inputSources.map(source => normalizeSource(source, issues));
  const sections = normalizedSources.map(source => ({
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
      `ELF relocations are required and remain unresolved in these DWARF sections: ` +
      `${relocationSections.map(source => source.summary.name).join(", ")}.`
    );
  }
  const sectionMap = buildSectionMap(normalizedSources, issues);
  return { sections, ...await readDwarfSectionAnalysis(sectionMap, byteOrder, addressSize, machine, issues),
    issues: [...new Set(issues)] };
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
