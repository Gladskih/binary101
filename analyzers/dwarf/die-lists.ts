import { DWARF_ATTRIBUTE } from "./constants.js";
import { DwarfIndexedReader } from "./indexed-tables.js";
import { readDwarfRangeList } from "./range-lists.js";
import { readDwarfLocationList } from "./location-lists.js";
import type { DwarfAttribute, DwarfDie, DwarfSectionSource, DwarfUnit } from "./types.js";

const resolveAddresses = async (unit: DwarfUnit, reader: DwarfIndexedReader): Promise<DwarfUnit> => {
  const dies: DwarfDie[] = [];
  for (const die of unit.dies) {
    const attributes: DwarfAttribute[] = [];
    for (const attribute of die.attributes) {
      const value = attribute.value.kind === "address-index"
        ? await reader.address(unit, attribute.value.value) : null;
      attributes.push(value == null ? attribute : {
        ...attribute, value: { kind: "unsigned", value }
      });
    }
    dies.push({ ...die, attributes });
  }
  return { ...unit, dies };
};

const readListAttribute = async (attribute: DwarfAttribute, unit: DwarfUnit,
  reader: DwarfIndexedReader, byteOrder: "little" | "big", issues: string[]): Promise<DwarfAttribute["value"]> => {
  if (attribute.name === DWARF_ATTRIBUTE.ranges) {
    const entries = await readDwarfRangeList(reader, unit, attribute);
    return entries == null ? attribute.value : { kind: "ranges", entries };
  }
  const entries = await readDwarfLocationList(reader, unit, attribute, byteOrder, issues);
  return entries == null ? attribute.value : { kind: "locations", entries };
};

const listKey = (attribute: DwarfAttribute): string | null => {
  if (attribute.value.kind !== "unsigned") return null;
  const kind = attribute.name === DWARF_ATTRIBUTE.ranges ? "ranges"
    : [DWARF_ATTRIBUTE.location, DWARF_ATTRIBUTE.frameBase].some(name => name === attribute.name)
      ? "locations" : null;
  return kind == null ? null : `${kind}:${attribute.form}:${attribute.value.value}`;
};

const readLists = async (
  unit: DwarfUnit, reader: DwarfIndexedReader, byteOrder: "little" | "big", issues: string[]
): Promise<DwarfUnit> => {
  const dies: DwarfDie[] = [];
  // The unit and all table bases are fixed: repeated references reuse the same decoded list.
  const cache = new Map<string, DwarfAttribute["value"]>();
  for (const die of unit.dies) {
    const attributes: DwarfAttribute[] = [];
    for (const attribute of die.attributes) {
      const key = listKey(attribute);
      if (key == null) { attributes.push(attribute); continue; }
      if (!cache.has(key)) {
        cache.set(key, await readListAttribute(attribute, unit, reader, byteOrder, issues));
      }
      attributes.push({ ...attribute, value: cache.get(key) ?? attribute.value });
    }
    dies.push({ ...die, attributes });
  }
  return { ...unit, dies };
};

export const decodeDwarfDieLists = async (
  units: DwarfUnit[], sections: Map<string, DwarfSectionSource>,
  byteOrder: "little" | "big", issues: string[]
): Promise<DwarfUnit[]> => {
  const reader = new DwarfIndexedReader(sections, byteOrder, issues);
  const decoded: DwarfUnit[] = [];
  for (const unit of units) {
    decoded.push(await readLists(await resolveAddresses(unit, reader), reader, byteOrder, issues));
  }
  return decoded;
};
