import { DWARF_ATTRIBUTE, DWARF_FORM } from "./constants.js";
import { decodeDwarfExpression } from "./expressions.js";
import type { DwarfDie, DwarfUnit } from "./types.js";

// Attributes accepting expression locations, including DWARF 2-3 block forms.
// DWARF 5 Appendix A, Table 7.5: https://dwarfstd.org/doc/DWARF5.pdf
const expressionAttributes = new Set<number>([
  DWARF_ATTRIBUTE.location, DWARF_ATTRIBUTE.frameBase, DWARF_ATTRIBUTE.dataMemberLocation,
  DWARF_ATTRIBUTE.byteSize, DWARF_ATTRIBUTE.bitSize, DWARF_ATTRIBUTE.count,
  DWARF_ATTRIBUTE.lowerBound, DWARF_ATTRIBUTE.upperBound,
  0x19, 0x2a, 0x2e, 0x4e, 0x4f, 0x50, 0x51, 0x71, 0x7e, 0x83, 0x84, 0x85, 0x86
]);

const decodeDie = async (
  die: DwarfDie, unit: DwarfUnit, byteOrder: "little" | "big", issues: string[]
): Promise<DwarfDie> => {
  const attributes = [];
  for (const attribute of die.attributes) {
    if (attribute.value.kind !== "block" ||
        (attribute.form !== DWARF_FORM.expressionLocation && !expressionAttributes.has(attribute.name))) {
      attributes.push(attribute);
      continue;
    }
    const notices: string[] = [];
    const operations = await decodeDwarfExpression(attribute.value.value, {
      version: unit.version, format: unit.format, addressSize: unit.addressSize, stringOffsetsBase: null
    }, byteOrder, notices);
    issues.push(...notices.map(notice => `${unit.sectionName} DIE at 0x${die.offset.toString(16)}: ${notice}`));
    attributes.push({ ...attribute, value: { kind: "expression" as const, operations } });
  }
  return { ...die, attributes };
};

export const decodeDwarfDieExpressions = async (
  units: DwarfUnit[], byteOrder: "little" | "big", issues: string[]
): Promise<DwarfUnit[]> => {
  const decoded: DwarfUnit[] = [];
  for (const unit of units) {
    const dies: DwarfDie[] = [];
    for (const die of unit.dies) dies.push(await decodeDie(die, unit, byteOrder, issues));
    decoded.push({ ...unit, dies });
  }
  return decoded;
};
