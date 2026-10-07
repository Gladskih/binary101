import { dwarfUnitRoot } from "./attribute-values.js";
import { dwarfPackageSectionName, dwarfSplitBaseName } from "./package-sections.js";
import type { DwarfPackageContribution } from "./package-types.js";
import type { DwarfAnalysis, DwarfLineProgram, DwarfUnit } from "./types.js";

export const dwarfUnitContribution = (dwarf: DwarfAnalysis, unit: DwarfUnit,
  sectionName: string): DwarfPackageContribution | null => {
  if (!unit.sectionName.endsWith(".dwo")) return null;
  for (const table of dwarf.packageIndexes ?? []) {
    const information = table.columns.findIndex(identifier =>
      dwarfPackageSectionName(table.version, identifier) === unit.sectionName);
    const column = table.columns.findIndex(identifier =>
      dwarfSplitBaseName(dwarfPackageSectionName(table.version, identifier) ?? "") === sectionName);
    if (information < 0 || column < 0) continue;
    const row = table.rows.find(row => row[information]!.offset === unit.offset);
    if (row) return row[column]!;
  }
  return null;
};

export const dwarfLineProgramForUnit = (dwarf: DwarfAnalysis,
  unit: DwarfUnit): DwarfLineProgram | undefined => {
  const split = unit.sectionName.endsWith(".dwo");
  const offset = dwarfUnitRoot(unit)?.statementListOffset ?? (split ? 0n : null);
  if (offset == null) return undefined;
  const base = dwarfUnitContribution(dwarf, unit, ".debug_line")?.offset ?? 0;
  return dwarf.linePrograms.find(program =>
    (program.sectionName ?? ".debug_line") === (split ? ".debug_line.dwo" : ".debug_line") &&
    BigInt(program.offset) === offset + BigInt(base));
};

export const dwarfSectionContributionAt = (dwarf: DwarfAnalysis,
  sectionName: string, offset: number, targetSectionName = sectionName): DwarfPackageContribution | null => {
  for (const table of dwarf.packageIndexes ?? []) {
    const column = table.columns.findIndex(identifier =>
      dwarfPackageSectionName(table.version, identifier) === sectionName);
    if (column < 0) continue;
    const targetColumn = table.columns.findIndex(identifier =>
      dwarfPackageSectionName(table.version, identifier) === targetSectionName);
    if (targetColumn < 0) continue;
    for (const row of table.rows) {
      const contribution = row[column]!;
      if (offset >= contribution.offset && offset < contribution.offset + contribution.size) {
        return row[targetColumn]!;
      }
    }
  }
  return null;
};
