import { dwarfPackageSectionName, dwarfSplitBaseName, isDwarfSplitSection } from "./package-sections.js";
import type { DwarfPackageContribution, DwarfPackageIndex } from "./package-types.js";
import type { DwarfSectionSource } from "./types.js";

export type DwarfSplitScope = {
  sections: Map<string, DwarfSectionSource>;
  contributions: Map<string, DwarfPackageContribution>;
};

const splitSectionMap = (sources: Map<string, DwarfSectionSource>): Map<string, DwarfSectionSource> => {
  const sections = new Map<string, DwarfSectionSource>();
  for (const [name, source] of sources) {
    if (!isDwarfSplitSection(name)) continue;
    const base = dwarfSplitBaseName(name);
    sections.set(base, { ...source, section: { ...source.section,
      name: base === ".debug_info" || base === ".debug_types" ? name : base } });
  }
  const addresses = sources.get(".debug_addr");
  if (addresses) sections.set(".debug_addr", addresses);
  return sections;
};

const packageScope = (table: DwarfPackageIndex, row: DwarfPackageContribution[],
  sources: Map<string, DwarfSectionSource>, issues: string[]): DwarfSplitScope | null => {
  const sections = new Map<string, DwarfSectionSource>();
  const contributions = new Map<string, DwarfPackageContribution>();
  for (const name of [".debug_str", ".debug_addr"]) {
    const source = sources.get(name);
    if (source) sections.set(name, source);
  }
  for (const [column, identifier] of table.columns.entries()) {
    const name = dwarfPackageSectionName(table.version, identifier);
    if (!name) continue;
    const contribution = row[column]!;
    if (!contribution.size) continue;
    if (!addContribution(name, contribution, sources, sections)) return null;
    contributions.set(dwarfSplitBaseName(name), contribution);
  }
  if (!hasRequiredSections(sections)) {
    issues.push(`${table.sectionName}: package row has no readable information or abbreviation contribution.`);
    return null;
  }
  return { sections, contributions };
};

const hasRequiredSections = (sections: Map<string, DwarfSectionSource>): boolean =>
  sections.has(".debug_abbrev") && (sections.has(".debug_info") || sections.has(".debug_types"));

const addContribution = (name: string, contribution: DwarfPackageContribution,
  sources: Map<string, DwarfSectionSource>, sections: Map<string, DwarfSectionSource>): boolean => {
  const base = dwarfSplitBaseName(name);
  const source = sources.get(base);
  if (!source || contribution.offset + contribution.size > source.section.size) return false;
  sections.set(base, { ...source, section: { ...source.section,
    offset: source.section.offset + contribution.offset, size: contribution.size } });
  return true;
};

export function* dwarfSplitScopes(sources: Map<string, DwarfSectionSource>,
  indexes: DwarfPackageIndex[], issues: string[]): Generator<DwarfSplitScope> {
  const sections = splitSectionMap(sources);
  if (!sources.has(".debug_cu_index") && !sources.has(".debug_tu_index")) {
    if (sections.has(".debug_info") || sections.has(".debug_types")) {
      yield { sections, contributions: new Map() };
    }
    return;
  }
  const overlapping = overlappingInformationRows(indexes, issues);
  for (const table of indexes) {
    for (const row of table.rows) {
      if (overlapping.has(row)) continue;
      const scope = packageScope(table, row, sections, issues);
      if (scope) yield scope;
    }
  }
}

const overlappingInformationRows = (indexes: DwarfPackageIndex[],
  issues: string[]): Set<DwarfPackageContribution[]> => {
  const rows = indexes.flatMap(table => {
    const name = table.version === 2 && table.sectionName === ".debug_tu_index"
      ? ".debug_types.dwo" : ".debug_info.dwo";
    const column = table.columns.findIndex(identifier => dwarfPackageSectionName(table.version, identifier) === name);
    return column < 0 ? [] : table.rows.flatMap(row => row[column]!.size
      ? [{ name, row, contribution: row[column]! }] : []);
  }).sort((left, right) => left.name.localeCompare(right.name) ||
    left.contribution.offset - right.contribution.offset);
  const overlapping = new Set<DwarfPackageContribution[]>();
  let previous: typeof rows[number] | null = null;
  for (const current of rows) {
    if (previous?.name === current.name &&
        current.contribution.offset < previous.contribution.offset + previous.contribution.size) {
      overlapping.add(previous.row);
      overlapping.add(current.row);
      issues.push(`${current.name}: overlapping package information contributions are not decoded.`);
    }
    if (!previous || previous.name !== current.name ||
        current.contribution.offset + current.contribution.size >
        previous.contribution.offset + previous.contribution.size) previous = current;
  }
  return overlapping;
};
