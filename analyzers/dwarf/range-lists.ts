import { DWARF_ATTRIBUTE } from "./constants.js";
import { dwarfAttributeValue, dwarfNumericValue } from "./attribute-values.js";
import {
  readDwarfListAddressEntry, validatedDwarfRange,
  type DwarfAddressEncoding
} from "./address-entries.js";
import type { DwarfIndexedReader } from "./indexed-tables.js";
import type { DwarfAddressRange, DwarfAttribute, DwarfUnit } from "./types.js";

// DW_RLE encodings: DWARF 5 Table 7.30 / section 2.17.3.
// https://dwarfstd.org/doc/DWARF5.pdf
const encodings: DwarfAddressEncoding[] = [
  "end", "base-index", "indexed-pair", "indexed-length", "offset-pair", "base", "pair", "length"
];

export const readDwarfRangeList = async (
  reader: DwarfIndexedReader, unit: DwarfUnit, attribute: DwarfAttribute
): Promise<DwarfAddressRange[] | null> => {
  const cursor = await reader.listCursor(unit, attribute,
    unit.version >= 5 ? ".debug_rnglists" : ".debug_ranges");
  if (!cursor) return null;
  const ranges: DwarfAddressRange[] = [];
  let selectedBase: bigint | null = dwarfNumericValue(
    dwarfAttributeValue(unit.dies[0], DWARF_ATTRIBUTE.lowPc)
  ) ?? 0n;
  while (cursor.position < cursor.end) {
    const entry = await readDwarfListAddressEntry(cursor, unit, reader, selectedBase, encodings, "range");
    if (!entry) break;
    if (entry.kind === "end") return ranges;
    if (entry.kind === "base") { selectedBase = entry.value; continue; }
    const range = validatedDwarfRange(cursor, entry, unit.addressSize);
    if (range) ranges.push(range);
  }
  cursor.notice("Range list has no end-of-list terminator");
  return ranges;
};
