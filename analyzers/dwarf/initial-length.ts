import type { DwarfCursor } from "./cursor.js";
import { DWARF_INITIAL_LENGTH } from "./constants.js";

// DWARF 5 7.2.2/7.4: initial lengths exclude their own encoded bytes.
// https://dwarfstd.org/doc/DWARF5.pdf
const initialFormat = (cursor: DwarfCursor, initial: number): 32 | 64 | null => {
  if (initial === DWARF_INITIAL_LENGTH.format64Escape) return 64;
  if (initial < DWARF_INITIAL_LENGTH.reservedMinimum) return 32;
  cursor.fail("reserved initial length");
  return null;
};

export const readDwarfInitialLength = async (
  cursor: DwarfCursor
): Promise<{ length: bigint; format: 32 | 64; end: number } | null> => {
  const initial = await cursor.uint32();
  if (initial == null) return null;
  const format = initialFormat(cursor, initial);
  if (format == null) return null;
  const length = format === 64 ? await cursor.uint64() : BigInt(initial);
  if (length == null) return null;
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) {
    cursor.fail("DWARF length is too large to index");
    return null;
  }
  if (length === 0n) cursor.notice("zero-length unit");
  const remaining = cursor.end - cursor.position;
  if (length > BigInt(remaining)) cursor.notice("unit extends beyond the section");
  return { length, format, end: cursor.position + Math.min(Number(length), remaining) };
};
