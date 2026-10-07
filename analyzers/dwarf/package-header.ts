import type { DwarfCursor } from "./cursor.js";
import type { DwarfPackageHeader } from "./package-types.js";

const readVersion = (cursor: DwarfCursor, word: number, byteOrder: "little" | "big"): 2 | 5 | null => {
  if (word === 2) return 2; // GNU v2 uses a uword; standard v5 uses version/padding uhalves.
  const version = byteOrder === "little" ? word & 0xffff : word >>> 16;
  const padding = byteOrder === "little" ? word >>> 16 : word & 0xffff;
  if (version === 5 && padding === 0) return 5;
  cursor.fail("Invalid DWARF package index version or padding");
  return null;
};

const validCounts = (cursor: DwarfCursor, sections: number, units: number, slots: number): boolean => {
  if (units && (!sections || !slots)) {
    cursor.fail("Nonempty DWARF package index has no section columns or signature slots");
    return false;
  }
  const required = BigInt(slots) * 12n + (BigInt(units) * 2n + 1n) * BigInt(sections) * 4n;
  if (required <= BigInt(cursor.end - cursor.position)) return true;
  cursor.fail("DWARF package index arrays exceed the section");
  return false;
};

// DWARF 5 7.3.5.3: header and matrix sizes are bounded before allocating or iterating.
export const readDwarfPackageHeader = async (cursor: DwarfCursor,
  byteOrder: "little" | "big"): Promise<DwarfPackageHeader | null> => {
  const word = await cursor.uint32();
  if (word == null) return null;
  const version = readVersion(cursor, word, byteOrder);
  if (!version) return null;
  const sectionCount = await cursor.uint32();
  const unitCount = await cursor.uint32();
  const slotCount = await cursor.uint32();
  if (cursor.failed) return null;
  if (!validCounts(cursor, sectionCount!, unitCount!, slotCount!)) return null;
  return { version, sectionCount: sectionCount!, unitCount: unitCount!, slotCount: slotCount! };
};
