import type { DwarfCursor } from "./cursor.js";
import type { DwarfAddressEntry } from "./address-entries.js";
import {
  readDwarfListAddressEntry, validatedDwarfRange,
  type DwarfAddressEncoding
} from "./address-entries.js";
import type { DwarfIndexedReader } from "./indexed-tables.js";
import { decodeDwarfExpression } from "./expressions.js";
import type { DwarfAttribute, DwarfLocationEntry, DwarfUnit } from "./types.js";

// DW_LLE encodings: DWARF 5 Table 7.29 / section 2.6.2.
// https://dwarfstd.org/doc/DWARF5.pdf
const encodings: DwarfAddressEncoding[] = [
  "end", "base-index", "indexed-pair", "indexed-length", "offset-pair",
  "default", "base", "pair", "length"
];

const readLocationExpression = async (cursor: DwarfCursor, entry: DwarfAddressEntry,
  unit: DwarfUnit, byteOrder: "little" | "big", issues: string[]): Promise<DwarfLocationEntry | null> => {
  const length = unit.version >= 5 ? await cursor.uleb() : await cursor.uint16();
  const bytes = length == null ? null : await cursor.bytes(length);
  if (!bytes) return null;
  const range = validatedDwarfRange(cursor, entry, unit.addressSize);
  if (!range && isResolvedRange(entry)) return null;
  return { range: entry.kind === "range" && !range ? "unresolved" : range,
    operations: await decodeDwarfExpression(bytes, {
    version: unit.version, format: unit.format, addressSize: unit.addressSize, stringOffsetsBase: null
  }, byteOrder, issues) };
};

const isResolvedRange = (entry: DwarfAddressEntry): boolean =>
  entry.kind === "range" && entry.start != null && entry.end != null;

export const readDwarfLocationList = async (
  reader: DwarfIndexedReader, unit: DwarfUnit, attribute: DwarfAttribute,
  byteOrder: "little" | "big", issues: string[]
): Promise<DwarfLocationEntry[] | null> => {
  const cursor = await reader.listCursor(unit, attribute,
    unit.version >= 5 ? ".debug_loclists" : ".debug_loc");
  if (!cursor) return null;
  const locations: DwarfLocationEntry[] = [];
  let base = reader.baseAddress(unit);
  while (cursor.position < cursor.end) {
    const entry = await readDwarfListAddressEntry(cursor, unit, reader, base, encodings, "location");
    if (!entry) break;
    if (entry.kind === "end") return locations;
    if (entry.kind === "base") { base = entry.value; continue; }
    const location = await readLocationExpression(cursor, entry, unit, byteOrder, issues);
    if (location) locations.push(location);
  }
  cursor.notice("Location list has no end-of-list terminator");
  return locations;
};
