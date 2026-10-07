import { dwarfSectionContributions } from "./section-contributions.js";
import type { DwarfCursor } from "./cursor.js";
import type { DwarfAddressLookup } from "./lookup-types.js";
import type { DwarfSectionSource, DwarfUnit } from "./types.js";

const terminator = (segment: bigint | null, start: bigint, length: bigint): boolean =>
  !segment && !start && !length;

const headerFieldsPresent = (cursor: DwarfCursor, addressSize: number | null): boolean =>
  !cursor.failed && addressSize != null;

// DWARF 5 6.1.2/7.21: tuples aligned relative to the contribution start.
// https://dwarfstd.org/doc/DWARF5.pdf
const readRanges = async (cursor: DwarfCursor, table: DwarfAddressLookup): Promise<void> => {
  const tupleSize = table.addressSize * 2 + table.segmentSize;
  const padding = (tupleSize - (cursor.position - table.offset) % tupleSize) % tupleSize;
  if (!cursor.skip(padding)) return;
  while (cursor.position < cursor.end) {
    const segment = table.segmentSize ? await cursor.unsigned(table.segmentSize) : null;
    const start = await cursor.unsigned(table.addressSize);
    const length = await cursor.unsigned(table.addressSize);
    if (cursor.failed) return;
    if (terminator(segment, start!, length!)) {
      if (cursor.position < cursor.end) cursor.notice("Trailing bytes after address lookup terminator");
      return;
    }
    if (start! + length! > 1n << BigInt(table.addressSize * 8)) {
      cursor.notice("Address lookup range exceeds the target address width");
    } else table.ranges.push({ segment, start: start!, length: length! });
  }
  cursor.notice("Address lookup contribution has no terminator");
};

export const readDwarfAddressLookup = async (source: DwarfSectionSource, units: DwarfUnit[],
  byteOrder: "little" | "big", issues: string[]): Promise<DwarfAddressLookup[]> => {
  const tables: DwarfAddressLookup[] = [];
  for await (const { cursor, offset, format } of dwarfSectionContributions(source, byteOrder, issues)) {
    const version = await cursor.uint16();
    const unitOffset = await cursor.unsigned(format / 8);
    const addressSize = await cursor.uint8();
    const segmentSize = await cursor.uint8();
    if (!headerFieldsPresent(cursor, addressSize)) continue;
    if (version !== 2 || !addressSize) { cursor.notice("Invalid address lookup header"); continue; }
    const table: DwarfAddressLookup = { offset, format, unitOffset: unitOffset!,
      addressSize: addressSize!, segmentSize: segmentSize!, ranges: [] };
    await readRanges(cursor, table);
    const unit = units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === unitOffset);
    if (!unit) cursor.notice("Address lookup references a missing compilation unit");
    else if (unit.addressSize !== addressSize) cursor.notice("Address lookup address-size mismatch");
    tables.push(table);
  }
  return tables;
};
