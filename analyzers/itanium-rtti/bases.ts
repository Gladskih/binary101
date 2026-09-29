import { readSignedWord } from "./records.js";
import type { ItaniumBase, ItaniumClassKind, ItaniumRttiImage } from "./types.js";

const readMultipleHeader = async (
  image: ItaniumRttiImage, address: number
): Promise<{ count: number; flags: number } | null> => {
  const width = image.pointerSize;
  const header = await image.read(address, 2 * width + 8);
  if (header.byteLength !== 2 * width + 8) return null;
  const flags = header.getUint32(2 * width, true);
  const count = header.getUint32(2 * width + 4, true);
  if (image.relocations.has(address + 2 * width) ||
      image.relocations.has(address + 2 * width + 4)) return null;
  // ABI 2.9.5: only repeat/diamond bits; bound work to 256 direct bases.
  if ((flags & ~3) !== 0 || count === 0 || count > 256) return null;
  return { count, flags };
};

const decodeBase = (
  image: ItaniumRttiImage, address: number, encoded: bigint
): ItaniumBase | null => {
  const typeAddress = image.pointers.get(address);
  if (image.relocations.has(address + image.pointerSize)) return null;
  // GCC uses long long under LLP64; the field is pointer-sized on both PE variants.
  // https://github.com/gcc-mirror/gcc/blob/master/libstdc++-v3/libsupc++/cxxabi.h
  const offset = Number(encoded >> 8n);
  if (typeAddress == null || (encoded & 252n) !== 0n || !Number.isSafeInteger(offset)) return null;
  const isVirtual = (encoded & 1n) !== 0n;
  if (isVirtual ? offset >= -2 * image.pointerSize || offset % image.pointerSize !== 0
    : offset < 0) return null;
  return { typeAddress, offset, isVirtual, isPublic: (encoded & 2n) !== 0n };
};

const readMultipleBases = async (
  image: ItaniumRttiImage, address: number
): Promise<{ bases: ItaniumBase[]; flags: number } | null> => {
  const header = await readMultipleHeader(image, address);
  if (!header) return null;
  const width = image.pointerSize;
  const start = address + 2 * width + 8;
  const view = await image.read(start, header.count * 2 * width);
  if (view.byteLength !== header.count * 2 * width) return null;
  const bases: ItaniumBase[] = [];
  for (let index = 0; index < header.count; index++) {
    const base = decodeBase(image, start + index * 2 * width,
      readSignedWord(view, index * 2 * width + width, width));
    if (!base || bases.some(previous => previous.typeAddress === base.typeAddress)) return null;
    bases.push(base);
  }
  return { bases, flags: header.flags };
};

export const readItaniumBases = async (
  image: ItaniumRttiImage, address: number, kind: ItaniumClassKind
): Promise<{ bases: ItaniumBase[]; flags?: number } | null> => {
  if (kind === "class") return { bases: [] };
  if (kind === "vmi") return readMultipleBases(image, address);
  if ((await image.read(address, 3 * image.pointerSize)).byteLength !== 3 * image.pointerSize) {
    return null;
  }
  const typeAddress = image.pointers.get(address + 2 * image.pointerSize);
  return typeAddress == null ? null : {
    bases: [{ typeAddress, offset: 0, isVirtual: false, isPublic: true }]
  };
};
