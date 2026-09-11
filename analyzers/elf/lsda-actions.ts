import type { ElfLsda, ElfLsdaCursorAt } from "./lsda-types.js";

// LLVM libcxxabi cxa_personality.cpp: action displacement is relative to the
// displacement field, not the record start or end. Positive filters index types;
// negative filters index exception-specification lists relative to the type base.
// https://raw.githubusercontent.com/llvm/llvm-project/main/libcxxabi/src/cxa_personality.cpp
export const readElfLsdaActions = (
  cursorAt: ElfLsdaCursorAt, actionStart: number, actionEnd: number, result: ElfLsda
): Promise<void> => readActionRoots(cursorAt, actionStart, actionEnd, result);

const validActionOffset = (offset: bigint, lower: number, upper: number): boolean =>
  offset >= BigInt(lower) && offset < BigInt(upper);

const readActionRoots = async (
  cursorAt: ElfLsdaCursorAt, actionStart: number, actionEnd: number, result: ElfLsda
): Promise<void> => {
  const complete = new Set<number>();
  for (const site of result.callSites) {
    if (site.action === 0n) continue;
    await readActionChain(cursorAt, BigInt(actionStart) + site.action - 1n, actionStart, actionEnd, complete, result);
    if (result.actions.length >= 100000) return;
  }
};

const readActionChain = async (
  cursorAt: ElfLsdaCursorAt, start: bigint, lower: number, upper: number,
  complete: Set<number>, result: ElfLsda
): Promise<void> => {
  let offset = start;
  const path = new Set<number>();
  while (!complete.has(Number(offset))) {
    if (!validActionOffset(offset, lower, upper)) {
      result.issues.push("LSDA action offset is outside the action table.");
      break;
    }
    if (path.has(Number(offset))) { result.issues.push("LSDA action chain has a cycle."); break; }
    path.add(Number(offset));
    const cursor = cursorAt(Number(offset), upper);
    const typeFilter = await cursor.sleb();
    const displacementOffset = cursor.position;
    const nextOffset = await cursor.sleb();
    if (typeFilter == null || nextOffset == null) break;
    result.actions.push({ offset: Number(offset), typeFilter, nextOffset });
    if (result.actions.length >= 100000) { result.issues.push("LSDA action limit reached."); break; }
    if (nextOffset === 0n) break;
    offset = BigInt(displacementOffset) + nextOffset;
  }
  for (const entry of path) complete.add(entry);
};
