import { DWARF_ATTRIBUTE, DWARF_TAG } from "../../analyzers/dwarf/constants.js";
import { dwarfNumericValue, dwarfStringValue } from "../../analyzers/dwarf/attribute-values.js";
import {
  inheritedDwarfAttribute, resolveDwarfReference,
  type DwarfDieIndex, type DwarfDieRecord
} from "../../analyzers/dwarf/references.js";
import { dwarfTagLabel } from "../../analyzers/dwarf/tag-names.js";

const prefixes = new Map<number, string>([
  [DWARF_TAG.pointerType, "pointer to "], [DWARF_TAG.referenceType, "reference to "],
  [DWARF_TAG.rvalueReferenceType, "rvalue reference to "]
]);
const qualifiers = new Map<number, string>([
  [DWARF_TAG.constType, "const "], [DWARF_TAG.volatileType, "volatile "],
  [DWARF_TAG.restrictType, "restrict "]
]);

const arraySuffix = (index: DwarfDieIndex, record: DwarfDieRecord): string =>
  (index.children.get(record.die) ?? []).filter(child =>
    child.die.tag === DWARF_TAG.subrangeType
  ).map(child => {
    const count = dwarfNumericValue(inheritedDwarfAttribute(index, child, DWARF_ATTRIBUTE.count)?.attribute.value);
    if (count != null) return `[${count}]`;
    const upper = dwarfNumericValue(inheritedDwarfAttribute(index, child, DWARF_ATTRIBUTE.upperBound)?.attribute.value);
    const lower = dwarfNumericValue(inheritedDwarfAttribute(index, child, DWARF_ATTRIBUTE.lowerBound)?.attribute.value);
    return upper == null ? "[]" : `[${lower ?? "?"}…${upper}]`;
  }).join("") || "[]";

const typeWrapper = (index: DwarfDieIndex, record: DwarfDieRecord): ((name: string) => string) | null => {
  const prefix = prefixes.get(record.die.tag) ?? qualifiers.get(record.die.tag);
  if (prefix) return text => prefix + text;
  if (record.die.tag !== DWARF_TAG.arrayType) return null;
  const dimensions = arraySuffix(index, record);
  return text => `array ${dimensions} of ${text}`;
};

export const dwarfTypeName = (index: DwarfDieIndex, start: DwarfDieRecord | null): string => {
  const visited = new Set<DwarfDieRecord>();
  const wrappers: Array<(name: string) => string> = [];
  let record = start;
  let name = "unspecified type";
  while (record) {
    if (visited.has(record)) { name = "recursive type"; break; }
    visited.add(record);
    const declared = dwarfStringValue(inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.name)?.attribute.value);
    if (declared) { name = declared; break; }
    const wrap = typeWrapper(index, record);
    if (!wrap) { name = dwarfTagLabel(record.die.tag).replaceAll("_", " "); break; }
    wrappers.push(wrap);
    const type = inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.type);
    record = type ? resolveDwarfReference(index, type.record, type.attribute) : null;
    if (!record) name = type ? "unresolved type" : "void";
  }
  return wrappers.reverse().reduce((text, wrap) => wrap(text), name);
};
