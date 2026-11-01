import type { ItaniumRttiImage } from "./types.js";

export interface StructuralName { value: string }

export const createNameStrings = (image: ItaniumRttiImage) => {
  const cache = new Map<number, Promise<StructuralName | null>>();
  const scan = async (target: number): Promise<StructuralName | null> => {
    let length = 0;
    const parts: string[] = [];
    while (Number.isSafeInteger(target + length)) {
      // ABI 2.9.5 specifies an NTBS without a length limit. Bound individual
      // reads to 4 KiB; retain the complete name until NUL or the mapped data ends.
      // https://itanium-cxx-abi.github.io/cxx-abi/abi.html#rtti-layout
      const view = await image.read(target + length, 4096);
      if (!view.byteLength) return null;
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const end = bytes.indexOf(0);
      const count = end < 0 ? bytes.length : end;
      length += count;
      parts.push(String.fromCharCode(...bytes.subarray(0, count)));
      if (end >= 0) return length ? { value: parts.join("") } : null;
    }
    return null;
  };
  return {
    read: (target: number): Promise<StructuralName | null> => {
      if (!cache.has(target)) cache.set(target, scan(target));
      return cache.get(target)!;
    }
  };
};
