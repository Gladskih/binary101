import type { DwarfCursor } from "./cursor.js";
import { readDwarfAttribute } from "./forms.js";
import type { DwarfNameAbbreviation } from "./name-index-abbreviations.js";
import type { DwarfNameIndexEntry } from "./name-index-types.js";
import type { DwarfAttribute } from "./types.js";

const readEntryAttributes = async (cursor: DwarfCursor, abbreviation: DwarfNameAbbreviation,
  format: 32 | 64): Promise<DwarfAttribute[]> => {
  const attributes: DwarfAttribute[] = [];
  for (const specification of abbreviation.attributes) {
    const attribute = await readDwarfAttribute(cursor, specification, {
      version: 5, format, addressSize: 0, stringOffsetsBase: null
    });
    if (!attribute) break;
    if (attributes.some(existing => existing.name === attribute.name)) cursor.notice("Duplicate name index attribute");
    attributes.push(attribute);
  }
  return attributes;
};

export const readDwarfNameEntries = async (cursor: DwarfCursor, base: number, format: 32 | 64,
  abbreviations: Map<bigint, DwarfNameAbbreviation>): Promise<DwarfNameIndexEntry[]> => {
  const entries: DwarfNameIndexEntry[] = [];
  while (cursor.position < cursor.end) {
    const offset = cursor.position - base;
    const code = await cursor.uleb();
    if (code == null) return entries;
    if (!code) return entries;
    const abbreviation = abbreviations.get(code);
    if (!abbreviation) { cursor.fail(`Unknown name index abbreviation ${code}`); return entries; }
    const attributes = await readEntryAttributes(cursor, abbreviation, format);
    entries.push({ offset, tag: abbreviation.tag, attributes });
    if (cursor.failed) return entries;
  }
  cursor.notice("Name entry list has no terminator");
  return entries;
};
