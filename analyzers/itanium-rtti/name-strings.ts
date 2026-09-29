import type { ItaniumRttiImage } from "./types.js";

// A validated NTBS can have no retained text. This does not invalidate its owner.
export interface StructuralName { value: string | null }

export const createNameStrings = (image: ItaniumRttiImage) => {
  const cache = new Map<number, Promise<StructuralName | null>>();
  // Resource policy, not an ABI name-length limit: bounded total scanning per image.
  let remaining = 64 * 1024 * 1024;
  let exhausted = false;
  const scan = async (target: number): Promise<StructuralName | null> => {
    let length = 0;
    let value: string | null = "";
    while (remaining > 0) {
      // ABI 2.9.5 specifies an NTBS without a length limit. Scan bounded chunks,
      // retaining at most 511 bytes for publication without truncating validation.
      // https://itanium-cxx-abi.github.io/cxx-abi/abi.html#rtti-layout
      const view = await image.read(target + length, Math.min(4096, remaining));
      if (!view.byteLength) return null;
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const end = bytes.indexOf(0);
      const count = end < 0 ? bytes.length : end;
      remaining -= count + (end < 0 ? 0 : 1);
      length += count;
      value = value != null && length <= 511
        ? value + String.fromCharCode(...bytes.subarray(0, count)) : null;
      if (end >= 0) return length ? { value } : null;
    }
    // Incomplete negative-space metadata must never permit positive vtable output.
    exhausted = true;
    return null;
  };
  return {
    get exhausted(): boolean { return exhausted; },
    read: (target: number): Promise<StructuralName | null> => {
      if (!cache.has(target)) cache.set(target, scan(target));
      return cache.get(target)!;
    }
  };
};
