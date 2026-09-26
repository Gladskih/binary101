import type { DRuntimeImage } from "./types.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../file-range-reader.js";

export const readDPointer = (image: DRuntimeImage, view: DataView, offset = 0): bigint =>
  image.pointerSize === 8
    ? view.getBigUint64(offset, image.littleEndian)
    : BigInt(view.getUint32(offset, image.littleEndian));

export const readDExact = async (
  image: DRuntimeImage, address: bigint, size: number
): Promise<DataView | null> => {
  const view = await image.read(address, size);
  return view?.byteLength === size ? view : null;
};

const appendPointers = (image: DRuntimeImage, view: DataView, pointers: bigint[],
  isValidAddress: (address: bigint) => boolean): boolean => {
  for (let index = 0; index < view.byteLength; index += image.pointerSize) {
    const pointer = readDPointer(image, view, index);
    if (!isValidAddress(pointer)) return false;
    pointers.push(pointer);
  }
  return true;
};

export const readDPointerArray = async (
  image: DRuntimeImage, address: bigint, isValidAddress: (address: bigint) => boolean = () => true
): Promise<bigint[] | null> => {
  const countView = await readDExact(image, address, image.pointerSize);
  if (!countView) return null;
  const count = readDPointer(image, countView);
  if (count === 0n) return [];
  const size = Number(count * BigInt(image.pointerSize));
  const start = address + BigInt(image.pointerSize);
  if (!Number.isSafeInteger(size) || !image.isMapped(start, size)) return null;
  const pointers: bigint[] = [];
  // The file bounds the array; the reader window bounds each temporary read only.
  for (let offset = 0; offset < size; offset += DEFAULT_FILE_READ_WINDOW_BYTES) {
    const view = await readDExact(image, start + BigInt(offset),
      Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, size - offset));
    if (!view) return null;
    if (!appendPointers(image, view, pointers, isValidAddress)) return null;
  }
  return pointers;
};

export const readDModuleName = async (
  image: DRuntimeImage, address: bigint
): Promise<string | null> => {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const parts: string[] = [];
    for (let location = address;;) {
      const view = await image.read(location, DEFAULT_FILE_READ_WINDOW_BYTES);
      if (!view?.byteLength) return null;
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const end = bytes.indexOf(0);
      parts.push(decoder.decode(end < 0 ? bytes : bytes.subarray(0, end), { stream: end < 0 }));
      if (end >= 0) return validateModuleName(parts.join(""));
      location += BigInt(view.byteLength);
    }
  } catch {
    return null;
  }
};

const validateModuleName = (name: string): string | null =>
  // DMD emits synthetic names (e.g. dbghelp.5460), not just identifiers.
  // https://github.com/dlang/dmd/blob/v2.112.0/druntime/src/object.d
  /^[\p{L}_][\p{L}\p{N}\p{M}_]*(?:\.[\p{L}\p{N}_][\p{L}\p{N}\p{M}_]*)*$/u.test(name) ? name : null;
