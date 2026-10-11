import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";

export type DecodedInstructionRange = { startRva: number; endRva: number };

const isBoundedRvaRange = (rva: number, length: number): boolean =>
  Number.isSafeInteger(rva) && rva >= 0 && Number.isSafeInteger(length) && length > 0 &&
  rva + length <= PE_RVA_EXCLUSIVE_LIMIT;

export const addDecodedInstructionRange = (
  ranges: DecodedInstructionRange[],
  instructionRva: number,
  length: number
): void => {
  if (!isBoundedRvaRange(instructionRva, length)) return;
  const endRva = instructionRva + length;
  // Large real PE traversals otherwise retain millions of per-instruction objects.
  // Coalesce the current run immediately; final merging still handles reordered runs.
  const previous = ranges.at(-1);
  if (previous && instructionRva <= previous.endRva && endRva >= previous.startRva) {
    previous.startRva = Math.min(previous.startRva, instructionRva);
    previous.endRva = Math.max(previous.endRva, endRva);
    return;
  }
  ranges.push({ startRva: instructionRva, endRva });
};

export const mergeDecodedInstructionRanges = (
  ranges: readonly DecodedInstructionRange[]
): DecodedInstructionRange[] => {
  const out: DecodedInstructionRange[] = [];
  const ordered = [...ranges].sort((left, right) =>
    left.startRva - right.startRva || left.endRva - right.endRva);
  for (const range of ordered) {
    const previous = out.at(-1);
    if (!previous || range.startRva > previous.endRva) {
      out.push({ ...range });
      continue;
    }
    previous.endRva = Math.max(previous.endRva, range.endRva);
  }
  return out;
};

export const overlapsDecodedInstructions = (
  ranges: readonly DecodedInstructionRange[],
  rva: number,
  byteLength: number
): boolean => {
  if (!isBoundedRvaRange(rva, byteLength)) return true;
  const endRva = rva + byteLength;
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const index = Math.floor((low + high) / 2);
    const range = ranges[index];
    if (!range) return false;
    if (range.endRva <= rva) {
      low = index + 1;
    } else if (range.startRva >= endRva) {
      high = index - 1;
    } else {
      return true;
    }
  }
  return false;
};
