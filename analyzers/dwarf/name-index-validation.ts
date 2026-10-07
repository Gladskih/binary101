import { dwarfNumericValue } from "./attribute-values.js";
import type { DwarfNameIndex, DwarfNameIndexEntry } from "./name-index-types.js";
import type { DwarfUnit } from "./types.js";

const attribute = (entry: DwarfNameIndexEntry, name: number): bigint | null =>
  dwarfNumericValue(entry.attributes.find(attribute => attribute.name === name)?.value);

const listValue = (values: bigint[], index: bigint | null): bigint | null =>
  index == null || index < 0n || index >= BigInt(values.length) ? null : values[Number(index)]!;

export const dwarfNameIndexUnit = (table: DwarfNameIndex, entry: DwarfNameIndexEntry,
  units: DwarfUnit[]): DwarfUnit | undefined => {
  const compileIndex = attribute(entry, 1);
  const typeIndex = attribute(entry, 2);
  if (typeIndex != null) {
    const local = listValue(table.localTypeUnits, typeIndex);
    if (local != null) return units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === local);
    const signature = listValue(table.foreignTypeUnits, typeIndex - BigInt(table.localTypeUnits.length));
    return signature == null ? undefined : units.find(unit => unit.typeSignature === signature);
  }
  const offset = listValue(table.compileUnits, compileIndex ?? (table.compileUnits.length === 1 ? 0n : null));
  return offset == null ? undefined : units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === offset);
};

const validateHashes = (table: DwarfNameIndex, issues: string[]): void => {
  if (!table.buckets.length) return;
  const first = new Map<number, number>();
  const completed = new Set<number>();
  let previous: number | null = null;
  for (const [index, name] of table.names.entries()) {
    const bucket = name.hash! % table.buckets.length;
    if (bucket !== previous) {
      if (completed.has(bucket)) issues.push(".debug_names: names for one hash bucket are not contiguous.");
      if (previous != null) completed.add(previous);
      previous = bucket;
    }
    if (!first.has(bucket)) first.set(bucket, index + 1);
  }
  for (const [bucket, index] of table.buckets.entries()) {
    if (index !== firstBucketIndex(first, bucket)) issues.push(".debug_names: hash bucket does not identify its first name.");
  }
};

const firstBucketIndex = (first: Map<number, number>, bucket: number): number => first.get(bucket) ?? 0;

const validParent = (entry: DwarfNameIndexEntry, offsets: Set<bigint>): boolean => {
  const value = entry.attributes.find(attribute => attribute.name === 4)?.value;
  return value?.kind !== "unsigned" || offsets.has(value.value);
};

const validateEntries = (table: DwarfNameIndex, units: DwarfUnit[], issues: string[]): void => {
  const offsets = new Set(table.names.flatMap(name => name.entries.map(entry => BigInt(entry.offset))));
  for (const entry of table.names.flatMap(name => name.entries)) {
    const unit = dwarfNameIndexUnit(table, entry, units);
    const dieOffset = attribute(entry, 3);
    const die = unit?.dies.find(die => BigInt(die.offset - unit.offset) === dieOffset);
    if (!die) issues.push(".debug_names: indexed entry has an unresolved compilation/type unit or DIE.");
    else if (die.tag !== entry.tag) issues.push(".debug_names: indexed tag disagrees with its DIE.");
    // DW_IDX_parent uses flag_present for an unindexed parent, ref4 for entry-pool references.
    if (!validParent(entry, offsets)) {
      issues.push(".debug_names: parent does not identify an entry-pool boundary.");
    }
    const relatedCu = attribute(entry, 1);
    if (relatedCu != null && listValue(table.compileUnits, relatedCu) == null) {
      issues.push(".debug_names: entry has an invalid related compilation-unit index.");
    }
  }
};

export const validateDwarfNameIndex = (table: DwarfNameIndex, units: DwarfUnit[], issues: string[]): void => {
  if (!table.compileUnits.length) issues.push(".debug_names: name index has no compilation units.");
  const offsets = new Set(units.filter(unit => unit.sectionName === ".debug_info").map(unit => BigInt(unit.offset)));
  for (const offset of [...table.compileUnits, ...table.localTypeUnits]) {
    if (!offsets.has(offset)) issues.push(".debug_names: unit list references a missing compilation/type unit.");
  }
  validateHashes(table, issues);
  validateEntries(table, units, issues);
};
