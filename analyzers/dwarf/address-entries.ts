import type { DwarfCursor } from "./cursor.js";
import type { DwarfIndexedReader } from "./indexed-tables.js";
import type { DwarfAddressRange, DwarfUnit } from "./types.js";

export type DwarfAddressEntry =
  | { kind: "end" }
  | { kind: "base"; value: bigint | null }
  | { kind: "range"; start: bigint | null; end: bigint | null }
  | { kind: "default" };
export type DwarfAddressEncoding = "end" | "base-index" | "indexed-pair" | "indexed-length" |
  "offset-pair" | "base" | "pair" | "length" | "default";

export const readLegacyDwarfAddressEntry = async (
  cursor: DwarfCursor, addressSize: number, base: bigint | null
): Promise<DwarfAddressEntry | null> => {
  const start = await cursor.unsigned(addressSize);
  const end = await cursor.unsigned(addressSize);
  if (start == null || end == null) return null;
  if (start === 0n && end === 0n) return { kind: "end" };
  // DWARF 4 2.17.3: all-ones start marks a base-address selection entry.
  // https://dwarfstd.org/doc/DWARF4.pdf
  if (start === (1n << BigInt(addressSize * 8)) - 1n) return { kind: "base", value: end };
  return { kind: "range", start: base == null ? null : base + start,
    end: base == null ? null : base + end };
};

const readAddressOperand = async (
  cursor: DwarfCursor, encoding: DwarfAddressEncoding, unit: DwarfUnit, reader: DwarfIndexedReader
): Promise<bigint | null> => {
  if (encoding === "base" || encoding === "pair" || encoding === "length") {
    return cursor.unsigned(unit.addressSize);
  }
  const value = await cursor.uleb();
  if (value == null || encoding === "offset-pair") return value;
  return reader.address(unit, value);
};

const readEndOperand = (
  cursor: DwarfCursor, encoding: DwarfAddressEncoding, unit: DwarfUnit, reader: DwarfIndexedReader
): Promise<bigint | null> => encoding === "length" || encoding === "indexed-length"
  ? (unit.version < 5 && encoding === "indexed-length" ? cursor.unsigned(4) : cursor.uleb())
  : readAddressOperand(cursor, encoding, unit, reader);

const offsetRange = (start: bigint, end: bigint, base: bigint | null): DwarfAddressEntry =>
  base == null ? { kind: "range", start: null, end: null }
    : { kind: "range", start: base + start, end: base + end };

const absoluteRange = (start: bigint, end: bigint, encoding: DwarfAddressEncoding): DwarfAddressEntry => ({
  kind: "range", start, end: encoding === "length" || encoding === "indexed-length" ? start + end : end
});

export const readDwarfAddressEntry = async (
  cursor: DwarfCursor, encoding: DwarfAddressEncoding,
  unit: DwarfUnit, reader: DwarfIndexedReader, base: bigint | null
): Promise<DwarfAddressEntry | null> => {
  if (encoding === "end" || encoding === "default") return { kind: encoding };
  const start = await readAddressOperand(cursor, encoding, unit, reader);
  if (encoding === "base" || encoding === "base-index") return { kind: "base", value: start };
  const end = await readEndOperand(cursor, encoding, unit, reader);
  if (cursor.failed) return null;
  if (start == null || end == null) return { kind: "range", start: null, end: null };
  return encoding === "offset-pair" ? offsetRange(start, end, base) : absoluteRange(start, end, encoding);
};

export const readDwarfListAddressEntry = async (
  cursor: DwarfCursor, unit: DwarfUnit, reader: DwarfIndexedReader, base: bigint | null,
  encodings: DwarfAddressEncoding[], kind: string
): Promise<DwarfAddressEntry | null> => {
  // GNU .debug_loc.dwo uses LLE opcodes before DWARF 5; its indexed length is u32.
  // https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/DebugInfo/DWARF/DWARFDebugLoc.cpp
  if (unit.version < 5 && !(kind === "location" && unit.sectionName.endsWith(".dwo"))) {
    return readLegacyDwarfAddressEntry(cursor, unit.addressSize, base);
  }
  const code = await cursor.uint8();
  if (code == null) return null;
  const encoding = encodings[code];
  if (!encoding) { cursor.fail(`Unknown ${kind}-list entry ${code}`); return null; }
  return readDwarfAddressEntry(cursor, encoding, unit, reader, base);
};

export const validatedDwarfRange = (
  cursor: DwarfCursor, entry: DwarfAddressEntry, addressSize: number
): DwarfAddressRange | null => {
  if (entry.kind !== "range") return null;
  if (entry.start == null || entry.end == null) {
    cursor.notice("Range cannot be resolved because an indexed address or base is unavailable");
    return null;
  }
  if (entry.start < 0n || entry.end < entry.start || entry.end >= 1n << BigInt(addressSize * 8)) {
    cursor.notice("Range ends before its start or exceeds the target address width");
    return null;
  }
  return { start: entry.start, end: entry.end };
};
