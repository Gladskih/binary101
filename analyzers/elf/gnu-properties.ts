import { bufferToHex } from "../../binary-utils.js";
import type { ElfByteOrder } from "./binary-layout-types.js";

export interface ElfGnuProperty {
  type: number;
  value: bigint | string;
}

// GNU property layout and types: glibc elf.h, x86/AArch64 psABIs.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const propertySize = (type: number, wordSize: number): number | null => {
  if (type === 1) return wordSize;
  if (type === 2) return 0;
  if ((type >= 0xb0000000 && type <= 0xb000ffff) ||
    [0xc0000000, 0xc0000002, 0xc0008002, 0xc0010002].includes(type)) return 4;
  return null;
};

const propertyValue = (
  type: number, data: Uint8Array, wordSize: number, order: ElfByteOrder, issues: string[]
): bigint | string => {
  const expected = propertySize(type, wordSize);
  if (expected == null) return bufferToHex(data);
  if (data.length !== expected) {
    issues.push(`GNU property 0x${type.toString(16)} has invalid data size ${data.length}.`);
    return bufferToHex(data);
  }
  if (!expected) return 0n;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return expected === 8 ? view.getBigUint64(0, order === "little") :
    BigInt(view.getUint32(0, order === "little"));
};

export const parseElfGnuProperties = (
  bytes: Uint8Array, wordSize: 4 | 8, order: ElfByteOrder, issues: string[]
): ElfGnuProperty[] => {
  const properties: ElfGnuProperty[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  let previous = -1;
  while (offset < bytes.length) {
    if (bytes.length - offset < 8) {
      issues.push("GNU property header is truncated.");
      break;
    }
    const type = view.getUint32(offset, order === "little");
    const size = view.getUint32(offset + 4, order === "little");
    offset += 8;
    if (size > bytes.length - offset) {
      issues.push("GNU property data is truncated.");
      break;
    }
    if (type <= previous) issues.push("GNU properties are not in strictly ascending type order.");
    previous = type;
    properties.push({ type,
      value: propertyValue(type, bytes.subarray(offset, offset + size), wordSize, order, issues) });
    offset += Math.ceil(size / wordSize) * wordSize;
    if (offset > bytes.length) issues.push("GNU property alignment padding is truncated.");
  }
  return properties;
};
