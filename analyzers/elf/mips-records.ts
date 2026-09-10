import { ELF_INTEGER_READERS } from "./byte-order.js";
import type { ElfByteOrder } from "./binary-layout-types.js";
import type { ElfMipsAbiFlags, ElfMipsRegInfo } from "./mips-types.js";

// LLVM definitions of Elf_Mips_ABIFlags and the distinct Elf32/64_Mips_RegInfo:
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/Object/ELFTypes.h
export const readMipsAbiFlags = (view: DataView, order: ElfByteOrder): ElfMipsAbiFlags | null => {
  if (view.byteLength < 24) return null;
  const integers = ELF_INTEGER_READERS[order];
  return { version: integers.u16(view, 0), isaLevel: view.getUint8(2), isaRevision: view.getUint8(3),
    gprSize: view.getUint8(4), cpr1Size: view.getUint8(5), cpr2Size: view.getUint8(6), fpAbi: view.getUint8(7),
    isaExtension: integers.u32(view, 8), ases: integers.u32(view, 12),
    flags1: integers.u32(view, 16), flags2: integers.u32(view, 20) };
};

export const readMips32RegInfo = (view: DataView, order: ElfByteOrder): ElfMipsRegInfo | null => {
  if (view.byteLength < 24) return null;
  const integers = ELF_INTEGER_READERS[order];
  return { gprMask: integers.u32(view, 0),
    cprMasks: [4, 8, 12, 16].map(offset => integers.u32(view, offset)),
    gpValue: BigInt(integers.u32(view, 20)) };
};

export const readMips64RegInfo = (view: DataView, order: ElfByteOrder): ElfMipsRegInfo | null => {
  if (view.byteLength < 32) return null;
  const integers = ELF_INTEGER_READERS[order];
  return { gprMask: integers.u32(view, 0),
    cprMasks: [8, 12, 16, 20].map(offset => integers.u32(view, offset)),
    gpValue: integers.u64(view, 24) };
};
