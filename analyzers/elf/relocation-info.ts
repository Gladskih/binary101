import type { ElfRelocationImage } from "./relocation-types.js";

// MIPS N64 stores r_sym as a word followed by ssym/type3/type2/type bytes,
// including in little-endian files. Preserve all four bytes of the type word.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/Object/ELFTypes.h
export const decodeElfRelocationInfo = (info: bigint, elf: ElfRelocationImage): {
  type: number; symbolIndex: number;
} => {
  if (!elf.is64) return { type: Number(info & 0xffn), symbolIndex: Number(info >> 8n) };
  if (elf.header.machine === 8 && elf.littleEndian) {
    return { symbolIndex: Number(info & 0xffff_ffffn), type:
      Number((info >> 56n & 0xffn) | (info >> 40n & 0xff00n) |
        (info >> 24n & 0xff0000n) | (info >> 8n & 0xff000000n)) };
  }
  return { type: Number(info & 0xffff_ffffn), symbolIndex: Number(info >> 32n) };
};
