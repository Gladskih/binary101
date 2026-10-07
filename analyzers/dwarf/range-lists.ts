import {
  readDwarfListAddressEntry, validatedDwarfRange,
  type DwarfAddressEncoding, type DwarfAddressEntry
} from "./address-entries.js";
import type { DwarfIndexedReader } from "./indexed-tables.js";
import type { DwarfCursor } from "./cursor.js";
import type { DwarfRangeEntry, DwarfAttribute, DwarfUnit } from "./types.js";

// DW_RLE encodings: DWARF 5 Table 7.30 / section 2.17.3.
// https://dwarfstd.org/doc/DWARF5.pdf
const encodings: DwarfAddressEncoding[] = [
  "end", "base-index", "indexed-pair", "indexed-length", "offset-pair", "base", "pair", "length"
];

const retainRange = (cursor: DwarfCursor, entry: DwarfAddressEntry,
  addressSize: number, ranges: DwarfRangeEntry[]): void => {
  const range = validatedDwarfRange(cursor, entry, addressSize);
  if (range) ranges.push(range);
  else if (entry.kind === "range" && (entry.start == null || entry.end == null)) {
    ranges.push({ kind: "unresolved" });
  }
};

export const readDwarfRangeList = async (
  reader: DwarfIndexedReader, unit: DwarfUnit, attribute: DwarfAttribute
): Promise<DwarfRangeEntry[] | null> => {
  const cursor = await reader.listCursor(unit, attribute,
    unit.version >= 5 ? ".debug_rnglists" : ".debug_ranges");
  if (!cursor) return null;
  const ranges: DwarfRangeEntry[] = [];
  let selectedBase = reader.baseAddress(unit);
  while (cursor.position < cursor.end) {
    const entry = await readDwarfListAddressEntry(cursor, unit, reader, selectedBase, encodings, "range");
    if (!entry) break;
    if (entry.kind === "end") return ranges;
    if (entry.kind === "base") { selectedBase = entry.value; continue; }
    retainRange(cursor, entry, unit.addressSize, ranges);
  }
  cursor.notice("Range list has no end-of-list terminator");
  return ranges;
};
