import { dwarfPackageSectionName } from "./package-sections.js";
import type { DwarfPackageContribution, DwarfPackageIndex } from "./package-types.js";
import type { DwarfSectionSource } from "./types.js";

const reachableSlot = (table: DwarfPackageIndex, slotIndex: number): boolean => {
  const signature = table.slots[slotIndex]!.signature;
  const mask = BigInt(table.slots.length - 1);
  let probe = Number(signature & mask);
  const step = Number(((signature >> 32n) & mask) | 1n);
  for (let count = 0; count < table.slots.length; count += 1) {
    const slot = table.slots[probe]!;
    if (!slot.row) return false;
    if (slot.signature === signature) return probe === slotIndex;
    probe = (probe + step) % table.slots.length;
  }
  return false;
};

const validateSlots = (table: DwarfPackageIndex, issues: string[]): void => {
  const usedRows = new Set<number>();
  const signatures = new Set<bigint>();
  for (const [position, slot] of table.slots.entries()) {
    if (!slot.row) {
      if (slot.signature) issues.push(`${table.sectionName}: unused signature slot is not zero.`);
      continue;
    }
    if (slot.row > table.rows.length || usedRows.has(slot.row)) {
      issues.push(`${table.sectionName}: invalid or repeated row index.`);
    }
    if (signatures.has(slot.signature)) issues.push(`${table.sectionName}: duplicate unit signature.`);
    if (!reachableSlot(table, position)) issues.push(`${table.sectionName}: signature slot is unreachable by its hash probe.`);
    usedRows.add(slot.row);
    signatures.add(slot.signature);
  }
  if (usedRows.size !== table.rows.length) issues.push(`${table.sectionName}: contribution rows are missing signature slots.`);
};

const contributionFits = (contribution: DwarfPackageContribution,
  source: DwarfSectionSource | undefined): boolean =>
  contribution.size === 0 || (source != null &&
    contribution.offset + contribution.size <= source.section.size);

const validateColumns = (table: DwarfPackageIndex,
  sources: Map<string, DwarfSectionSource>, issues: string[]): void => {
  const seen = new Set<number>();
  for (const [column, identifier] of table.columns.entries()) {
    const name = dwarfPackageSectionName(table.version, identifier);
    if (!name || seen.has(identifier)) {
      issues.push(`${table.sectionName}: unknown or duplicate section identifier ${identifier}.`);
    }
    seen.add(identifier);
    for (const row of table.rows) {
      if (!contributionFits(row[column]!, name ? sources.get(name) : undefined)) {
        issues.push(`${table.sectionName}: contribution for section ${identifier} is missing or outside its section.`);
      }
    }
  }
  validateRequiredColumns(table, seen, issues);
};

const validateRequiredColumns = (table: DwarfPackageIndex,
  seen: Set<number>, issues: string[]): void => {
  const information = table.version === 2 && table.sectionName === ".debug_tu_index" ? 2 : 1;
  if (table.rows.length && (!seen.has(information) || !seen.has(3))) {
    issues.push(`${table.sectionName}: required information or abbreviation column is missing.`);
  }
};

export const validateDwarfPackageIndex = (table: DwarfPackageIndex,
  sources: Map<string, DwarfSectionSource>, issues: string[]): void => {
  const slots = BigInt(table.slots.length);
  if (slots && ((slots & (slots - 1n)) !== 0n || slots * 2n <= BigInt(table.rows.length) * 3n)) {
    issues.push(`${table.sectionName}: hash slot count is not a valid power of two or load factor.`);
  }
  validateSlots(table, issues);
  validateColumns(table, sources, issues);
};
