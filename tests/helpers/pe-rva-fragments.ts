import { MockFile } from "./mock-file.js";
import type { RvaToOffset } from "../../analyzers/pe/types.js";

/** Noncontiguous file storage with deliberately misleading bytes after each fragment. */
export const createPeRvaFragments = (
  rva: number, bytes: Uint8Array, split: number,
  firstOffset = 16, nextOffset = bytes.length + 32
) => {
  const data = new Uint8Array(Math.max(firstOffset + split,
    nextOffset + bytes.length - split)).fill(0xcc);
  data.set(bytes.subarray(0, split), firstOffset);
  data.set(bytes.subarray(split), nextOffset);
  const mapping: RvaToOffset = address => {
    const delta = address - rva;
    if (delta < 0 || delta >= bytes.length) return null;
    return delta < split ? firstOffset + delta : nextOffset + delta - split;
  };
  return { reader: new MockFile(data), mapping };
};
