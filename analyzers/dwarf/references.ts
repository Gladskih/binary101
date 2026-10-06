import { DWARF_ATTRIBUTE, DWARF_FORM, DWARF_SECTION } from "./constants.js";
import { dwarfNumericValue } from "./attribute-values.js";
import type { DwarfAttribute, DwarfDie, DwarfUnit } from "./types.js";

export type DwarfDieRecord = { unit: DwarfUnit; die: DwarfDie };
export type DwarfDieIndex = {
  records: DwarfDieRecord[];
  byOffset: Map<string, DwarfDieRecord>;
  bySignature: Map<bigint, DwarfDieRecord>;
  children: Map<DwarfDie, DwarfDieRecord[]>;
};

const localReferenceForms = new Set<number>([
  DWARF_FORM.reference1, DWARF_FORM.reference2, DWARF_FORM.reference4,
  DWARF_FORM.reference8, DWARF_FORM.referenceUnsigned
]);

export const isDwarfDieReference = (form: number): boolean =>
  localReferenceForms.has(form) || [DWARF_FORM.referenceAddress, DWARF_FORM.referenceSignature8,
    DWARF_FORM.referenceSupplementary4, DWARF_FORM.referenceSupplementary8,
    DWARF_FORM.gnuReferenceAlternate].some(code => code === form);

export const createDwarfDieIndex = (units: DwarfUnit[]): DwarfDieIndex => {
  const records = units.flatMap(unit => unit.dies.map(die => ({ unit, die })));
  const byOffset = new Map(records.map(record => [
    `${record.unit.sectionName}:${record.die.offset}`, record
  ]));
  const bySignature = new Map<bigint, DwarfDieRecord>();
  const children = new Map<DwarfDie, DwarfDieRecord[]>();
  for (const record of records) {
    const parent = record.die.parentOffset == null ? null
      : byOffset.get(`${record.unit.sectionName}:${record.die.parentOffset}`);
    if (parent) {
      const siblings = children.get(parent.die) ?? [];
      siblings.push(record);
      children.set(parent.die, siblings);
    }
    if (record.unit.typeSignature != null && record.unit.typeOffset != null &&
        BigInt(record.die.offset) === BigInt(record.unit.offset) + record.unit.typeOffset) {
      bySignature.set(record.unit.typeSignature, record);
    }
  }
  return { records, byOffset, bySignature, children };
};

export const resolveDwarfReference = (
  index: DwarfDieIndex, record: DwarfDieRecord, attribute: DwarfAttribute | undefined
): DwarfDieRecord | null => {
  if (!attribute) return null;
  const value = dwarfNumericValue(attribute.value);
  if (value == null || value < 0n) return null;
  return resolveReferenceValue(index, record, attribute, value);
};

const resolveReferenceValue = (
  index: DwarfDieIndex, record: DwarfDieRecord, attribute: DwarfAttribute, value: bigint
): DwarfDieRecord | null => {
  if (attribute.form === DWARF_FORM.referenceSignature8) {
    return index.bySignature.get(value) ?? null;
  }
  if (attribute.form === DWARF_FORM.referenceAddress) {
    return index.byOffset.get(`${DWARF_SECTION.information}:${value}`) ?? null;
  }
  if (!localReferenceForms.has(attribute.form)) return null;
  const target = index.byOffset.get(`${record.unit.sectionName}:${BigInt(record.unit.offset) + value}`);
  return target?.unit === record.unit ? target : null;
};

export const inheritedDwarfAttribute = (
  index: DwarfDieIndex, record: DwarfDieRecord, name: number
): { record: DwarfDieRecord; attribute: DwarfAttribute } | undefined => {
  const pending = [record];
  const visited = new Set<DwarfDie>();
  while (pending.length) {
    const current = pending.pop()!;
    if (visited.has(current.die)) continue;
    visited.add(current.die);
    const direct = current.die.attributes.find(item => item.name === name);
    if (direct) return { record: current, attribute: direct };
    for (const link of [DWARF_ATTRIBUTE.specification, DWARF_ATTRIBUTE.abstractOrigin]) {
      const target = resolveDwarfReference(index, current,
        current.die.attributes.find(item => item.name === link));
      if (target) pending.push(target);
    }
  }
  return undefined;
};

const inheritanceTargets = (index: DwarfDieIndex, record: DwarfDieRecord): DwarfDieRecord[] =>
  [DWARF_ATTRIBUTE.specification, DWARF_ATTRIBUTE.abstractOrigin].flatMap(name => {
    const target = resolveDwarfReference(index, record,
      record.die.attributes.find(attribute => attribute.name === name));
    return target ? [target] : [];
  });

const validateInheritanceCycles = (index: DwarfDieIndex, issues: string[]): void => {
  const complete = new Set<DwarfDieRecord>();
  const active = new Set<DwarfDieRecord>();
  for (const record of index.records) {
    if (complete.has(record)) continue;
    const pending = [{ record, targets: inheritanceTargets(index, record) }];
    active.add(record);
    while (pending.length) {
      const current = pending.at(-1)!;
      const target = current.targets.pop();
      if (!target) {
        active.delete(current.record);
        complete.add(current.record);
        pending.pop();
      } else if (active.has(target)) {
        issues.push(`${target.unit.sectionName} DIE at 0x${target.die.offset.toString(16)}: ` +
          `Cyclic specification/abstract_origin references.`);
      } else if (!complete.has(target)) {
        active.add(target);
        pending.push({ record: target, targets: inheritanceTargets(index, target) });
      }
    }
  }
};

export const validateDwarfReferences = (index: DwarfDieIndex, issues: string[]): void => {
  for (const record of index.records) {
    for (const attribute of record.die.attributes) {
      if (!isDwarfDieReference(attribute.form)) continue;
      if (!resolveDwarfReference(index, record, attribute)) {
        issues.push(`${record.unit.sectionName} DIE at 0x${record.die.offset.toString(16)}: ` +
          `unresolved DIE reference in attribute 0x${attribute.name.toString(16)}.`);
      }
    }
  }
  validateInheritanceCycles(index, issues);
};
