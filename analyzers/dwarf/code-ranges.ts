import { dwarfAttributeValue, dwarfNumericValue } from "./attribute-values.js";
import type { DwarfAddressRange, DwarfAttribute, DwarfDie } from "./types.js";

// DWARF 5 2.17.2: high_pc is either an address or a constant offset from low_pc.
// Address forms: DWARF 5 Table 7.5. https://dwarfstd.org/doc/DWARF5.pdf
const addressForms = new Set([0x01, 0x1b, 0x29, 0x2a, 0x2b, 0x2c, 0x1f01]);
const constantForms = new Set([0x05, 0x06, 0x07, 0x0b, 0x0d, 0x0f, 0x21]);

const rangeEnd = (start: bigint, high: DwarfAttribute): bigint | null => {
  const value = dwarfNumericValue(high.value);
  if (value == null) return null;
  if (addressForms.has(high.form)) return value;
  return constantForms.has(high.form) ? start + value : null;
};

export const dwarfCodeRanges = (die: DwarfDie): DwarfAddressRange[] => {
  const ranges = dwarfAttributeValue(die, 0x55); // DW_AT_ranges, Table 7.3.
  if (ranges?.kind === "ranges") return ranges.entries.filter(range => "start" in range);
  const start = dwarfNumericValue(dwarfAttributeValue(die, 0x11)); // DW_AT_low_pc.
  const high = die.attributes.find(attribute => attribute.name === 0x12); // DW_AT_high_pc.
  if (start == null || !high) return [];
  const end = rangeEnd(start, high);
  return end == null || start < 0n || end < start ? [] : [{ start, end }];
};

export const dwarfCodeSize = (die: DwarfDie): bigint | null => {
  const listed = dwarfAttributeValue(die, 0x55);
  if (listed?.kind === "ranges" && listed.entries.some(range => "kind" in range)) return null;
  const ranges = [...dwarfCodeRanges(die)].sort((left, right) =>
    left.start < right.start ? -1 : left.start > right.start ? 1 : 0);
  if (!ranges.length) return null;
  let size = 0n;
  let end = ranges[0]!.start;
  for (const range of ranges) {
    if (range.end <= end) continue;
    size += range.end - (range.start > end ? range.start : end);
    end = range.end;
  }
  return size;
};
