import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfLsda, ElfLsdaCursorAt } from "./lsda-types.js";
import { readElfUnwindPointer } from "./unwind-pointer.js";

export const readElfLsdaCallSites = async (
  cursor: DwarfCursor, addressSize: number, result: ElfLsda
): Promise<void> => {
  if ((result.callSiteEncoding & 0xf0) !== 0) {
    cursor.fail("Unsupported LSDA call-site encoding");
    return;
  }
  while (cursor.position < cursor.end && !cursor.failed) {
    const start = await readElfUnwindPointer(cursor, result.callSiteEncoding, addressSize, 0n);
    const length = await readElfUnwindPointer(cursor, result.callSiteEncoding, addressSize, 0n);
    const landingPad = await readElfUnwindPointer(cursor, result.callSiteEncoding, addressSize, 0n);
    const action = await cursor.uleb();
    if (!start || !length || !landingPad || action == null) break;
    result.callSites.push({ start: start.address, length: length.address, landingPad: landingPad.address, action });
    if (result.callSites.length === 100000) { cursor.fail("LSDA call-site limit reached"); break; }
  }
  validateCallSites(result);
};

const validateCallSites = (result: ElfLsda): void => {
  let end = 0n;
  for (const site of result.callSites) {
    if (site.start < end || site.length < 0n || site.landingPad < 0n) {
      result.issues.push("LSDA call-site ranges are negative, overlapping or out of order.");
      return;
    }
    end = site.start + site.length;
  }
};

export const readElfLsdaTypes = async (
  cursorAt: ElfLsdaCursorAt, typeBase: number | null, addressSize: number, result: ElfLsda
): Promise<void> => {
  if (typeBase == null) {
    if (result.actions.some(action => action.typeFilter !== 0n)) result.issues.push("LSDA action requires a missing type table.");
    return;
  }
  const indices = new Set(result.actions.filter(action => action.typeFilter > 0n).map(action => action.typeFilter));
  await readSpecifications(cursorAt, typeBase, indices, result);
  const width = typeWidth(result.typeEncoding, addressSize);
  if (width == null) { result.issues.push("LSDA reverse type table requires a fixed-width encoding."); return; }
  for (const index of indices) {
    const offset = BigInt(typeBase) - index * BigInt(width);
    if (offset < 0n) { result.issues.push("LSDA type index is outside the descriptor."); continue; }
    const pointer = await readElfUnwindPointer(cursorAt(Number(offset), typeBase),
      result.typeEncoding, addressSize, result.address);
    result.types.push({ index, pointer });
  }
};

const typeWidth = (encoding: number, addressSize: number): number | undefined =>
  ({ 0: addressSize, 2: 2, 3: 4, 4: 8, 10: 2, 11: 4, 12: 8 } as Record<number, number>)[encoding & 15];

const readSpecifications = async (
  cursorAt: ElfLsdaCursorAt, typeBase: number, indices: Set<bigint>, result: ElfLsda
): Promise<void> => {
  const filters = new Set(result.actions.filter(action => action.typeFilter < 0n).map(action => action.typeFilter));
  for (const filter of filters) {
    const offset = BigInt(typeBase) - filter - 1n;
    const cursor = cursorAt(Number(offset));
    const typeIndices: bigint[] = [];
    while (!cursor.failed && typeIndices.length < 100000) {
      const index = await cursor.uleb();
      if (index == null || index === 0n) break;
      typeIndices.push(index);
      indices.add(index);
    }
    if (typeIndices.length === 100000) cursor.fail("LSDA exception specification limit reached");
    result.specifications.push({ filter, typeIndices });
  }
};
