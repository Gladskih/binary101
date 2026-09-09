import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfUnwindCie, ElfUnwindFde, ElfUnwindPointer } from "./unwind-types.js";
import { readElfUnwindPointer } from "./unwind-pointer.js";
import { readElfCfiInstructions } from "./cfi-instructions.js";

const readLsda = async (
  cursor: DwarfCursor, cie: ElfUnwindCie, sectionAddress: bigint
): Promise<ElfUnwindPointer | null> => {
  if (!cie.augmentation.startsWith("z")) return null;
  const size = await cursor.uleb();
  if (size == null) return null;
  const end = cursor.position + Number(size);
  if (!Number.isSafeInteger(end) || end > cursor.end) {
    cursor.fail("FDE augmentation is truncated");
    return null;
  }
  const lsda = await readElfUnwindPointer(cursor, cie.lsdaEncoding, cie.addressSize, sectionAddress);
  cursor.skip(end - cursor.position);
  return lsda;
};

export const readElfUnwindFde = async (
  cursor: DwarfCursor, offset: number, cie: ElfUnwindCie, sectionAddress: bigint, machine: number
): Promise<ElfUnwindFde | null> => {
  // LSB 10.6.1.2: PC range uses only the format bits, never a relative base/indirection.
  const start = await readElfUnwindPointer(cursor, cie.fdeEncoding, cie.addressSize, sectionAddress);
  const range = await readElfUnwindPointer(cursor, cie.fdeEncoding & 15, cie.addressSize, 0n);
  const lsda = await readLsda(cursor, cie, sectionAddress);
  if (cursor.failed || !range) return null;
  if (range.address < 0n) {
    cursor.fail("FDE PC range is negative");
    return null;
  }
  return { offset, cieOffset: cie.offset, start, range: range.address, lsda,
    instructions: await readElfCfiInstructions(cursor, cie.addressSize, machine) };
};
