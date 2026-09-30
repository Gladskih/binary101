import type { ItaniumRttiImage } from "./types.js";
import { createNameStrings, type StructuralName } from "./name-strings.js";

export const createNames = (image: ItaniumRttiImage) => {
  const names = new Map<number, Promise<string | null>>();
  const headers = new Map<number, boolean>();
  const strings = createNameStrings(image);
  const structuralNames = new Map<number, Promise<StructuralName | null>>();
  const header = async (address: number): Promise<boolean> => {
    if (!headers.has(address)) headers.set(address,
      (await image.read(address, 2 * image.pointerSize)).byteLength === 2 * image.pointerSize);
    return headers.get(address)!;
  };
  const readName = async (address: number): Promise<StructuralName | null> => {
    if (address % image.pointerSize !== 0) return null;
    const target = image.pointers.get(address + image.pointerSize);
    if (target == null || !image.relocations.has(address + image.pointerSize)) return null;
    if (!await header(address)) return null;
    return strings.read(target);
  };
  const structuralName = (address: number): Promise<StructuralName | null> => {
    if (!structuralNames.has(address)) structuralNames.set(address, readName(address));
    return structuralNames.get(address)!;
  };
  const name = (address: number): Promise<string | null> => {
    if (!names.has(address)) names.set(address, structuralName(address).then(name => name?.value ?? null));
    return names.get(address)!;
  };
  return { name,
    get exhausted(): boolean { return strings.exhausted; },
    prepare: async (addresses: Iterable<number>): Promise<void> => {
      const ordered = [...new Set(addresses)].filter(address => !structuralNames.has(address))
        .sort((left, right) => image.readOrder(left) - image.readOrder(right));
      // Separate physical passes avoid bouncing between type records and distant names.
      for (const address of ordered) await header(address);
      ordered.sort((left, right) => image.readOrder(image.pointers.get(left + image.pointerSize)!) -
        image.readOrder(image.pointers.get(right + image.pointerSize)!));
      for (const address of ordered) await structuralName(address);
    }
  };
};
