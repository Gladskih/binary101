import { FH3_LAYOUT } from "./layout.js";
import type { EhFunctionInfo, EhImage } from "./types.js";
import { MAX_TYPE_DESCRIPTOR_NAME_BYTES, TYPE_DESCRIPTOR_POINTER_FIELDS }
  from "../msvc/type-descriptor-layout.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARMNT } from "../../coff/machine.js";

export const validEhState = (state: number, count: number): boolean => state >= -1 && state < count;

export const ehMetadataRva = (image: EhImage, value: number): number => value === 0 ? 0 :
  image.core.coff.Machine === IMAGE_FILE_MACHINE_I386 ? Number(BigInt(value) - image.core.opt.ImageBase) : value;

export const ehCodeRva = (image: EhImage, value: number): number => {
  const rva = ehMetadataRva(image, value);
  return image.core.coff.Machine === IMAGE_FILE_MACHINE_ARMNT ? rva - (rva & 1) : rva;
};

export const readEhTable = (
  image: EhImage, rva: number, count: number, stride: number
): { count: number; read: (index: number) => Promise<DataView | null> } | null => {
  if (!Number.isSafeInteger(count) || count < 0 || (count === 0) !== (rva === 0) || rva % FH3_LAYOUT.alignment ||
      !Number.isSafeInteger(stride) || stride <= 0) return null;
  if (count > Math.floor(image.available(rva) / stride)) return null;
  return { count, read: (index: number) => Number.isSafeInteger(index) && index >= 0 && index < count
    ? image.read(rva + index * stride, stride) : Promise.resolve(null) };
};

const validCatchHeader = (header: DataView, pointerSize: 4 | 8): boolean => {
  const vftable = pointerSize === 8 ? header.getBigUint64(0, true) : BigInt(header.getUint32(0, true));
  const spare = pointerSize === 8
    ? header.getBigUint64(pointerSize, true) : BigInt(header.getUint32(pointerSize, true));
  return vftable !== 0n && spare === 0n &&
    header.getUint8(pointerSize * TYPE_DESCRIPTOR_POINTER_FIELDS) === 0x2e; // '.'; int is ".H".
};

const hasTerminatedTypeName = (name: DataView): boolean => {
  // MicrosoftCXXABI stores a NUL-terminated decorated ASCII name after the native pointers.
  // Only raw descriptor RVAs are exposed here; this check never guesses a source-language type.
  for (let offset = 0; offset < name.byteLength; offset++) {
    const byte = name.getUint8(offset);
    if (byte === 0) return offset > 0;
    if (byte < 0x21 || byte > 0x7e) return false;
  }
  return false;
};

const readCatchType = async (image: EhImage, rva: number): Promise<boolean> => {
  if (!rva) return true; // CRT catch (...) has a null TypeDescriptor.
  // MSVC ehdata.h / TypeDescriptor: two pointer-sized fields, then a decorated name.
  const pointerSize = image.core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4;
  const header = await image.read(rva, pointerSize * TYPE_DESCRIPTOR_POINTER_FIELDS + 2);
  if (!header || !validCatchHeader(header, pointerSize)) return false;
  // Share the RTTI name-length policy. Longer names stay unvalidated, never guessed.
  const start = rva + pointerSize * TYPE_DESCRIPTOR_POINTER_FIELDS + 1;
  const name = await image.read(start, Math.min(image.available(start), MAX_TYPE_DESCRIPTOR_NAME_BYTES));
  return name != null && hasTerminatedTypeName(name);
};

export const validCatchType = (image: EhImage, rva: number): Promise<boolean> => {
  const cached = image.typeValidity.get(rva);
  if (cached) return cached;
  const result = readCatchType(image, rva);
  image.typeValidity.set(rva, result);
  return result;
};

export const validateEhFunctionLinks = (
  info: EhFunctionInfo, covers: (rva: number) => boolean
): boolean => info.ipStates.length > 0 && info.ipStates.every(entry => covers(entry.ipRva));
