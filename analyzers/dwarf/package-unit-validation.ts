import { dwarfPackageSectionName } from "./package-sections.js";
import { dwarfSplitIdentity } from "./external-files.js";
import type { DwarfPackageIndex } from "./package-types.js";
import type { DwarfUnit } from "./types.js";

export const validateDwarfPackageUnits = (tables: DwarfPackageIndex[],
  units: DwarfUnit[], issues: string[]): void => {
  const byOffset = new Map(units.map(unit => [`${unit.sectionName}:${unit.offset}`, unit]));
  for (const table of tables) {
    const information = table.version === 2 && table.sectionName === ".debug_tu_index" ? 2 : 1;
    const column = table.columns.indexOf(information);
    if (column < 0) continue;
    for (const [index, row] of table.rows.entries()) {
      const contribution = row[column]!;
      const unit = byOffset.get(`${dwarfPackageSectionName(table.version, information)}:${contribution.offset}`);
      if (!unit) { issues.push(`${table.sectionName}: package row has no decoded unit.`); continue; }
      validateEncoding(table, unit, contribution.size, issues);
      validateSignature(table, index + 1, unit, issues);
    }
  }
};

const validateEncoding = (table: DwarfPackageIndex, unit: DwarfUnit,
  contributionSize: number, issues: string[]): void => {
  if (unit.abbreviationOffset !== 0n) issues.push(`${table.sectionName}: package unit has a nonzero abbreviation offset.`);
  if (unit.length + BigInt(unit.format === 32 ? 4 : 12) !== BigInt(contributionSize)) {
    issues.push(`${table.sectionName}: package contribution length disagrees with its unit.`);
  }
};

const validateSignature = (table: DwarfPackageIndex, row: number,
  unit: DwarfUnit, issues: string[]): void => {
  const slot = table.slots.find(slot => slot.row === row);
  const signature = table.sectionName === ".debug_tu_index" ? unit.typeSignature : dwarfSplitIdentity(unit);
  if (!slot || signature == null || slot.signature !== signature) {
    issues.push(`${table.sectionName}: package signature disagrees with its compilation/type unit.`);
  }
};
