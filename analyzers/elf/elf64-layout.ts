import { ELF_INTEGER_READERS, type ElfIntegerReader } from "./byte-order.js";
import type { ElfBinaryLayout, ElfByteOrder, ElfSymbolRecord,
  ElfSymbolicRelocationRecord } from "./binary-layout-types.js";
import { ELF_MACHINE_ID, ELF_SYMBOL_INDEX } from "./abi-constants.js";

// Fixed Elf64 layouts, field byte offsets and ELF64_R_SYM/TYPE masks:
// https://gabi.xinuos.com/elf/05-symtab.html (Elf64_Sym, 24 bytes)
// https://gabi.xinuos.com/elf/06-reloc.html (Elf64_Rel, 16; Elf64_Rela, 24)
// https://gabi.xinuos.com/elf/08-dynamic.html (Elf64_Dyn, 16)
const readSymbol = (view: DataView, integers: ElfIntegerReader): ElfSymbolRecord | null =>
  view.byteLength < 24 ? null : {
    nameOffset: integers.u32(view, 0), info: view.getUint8(4), other: view.getUint8(5),
    sectionIndex: integers.u16(view, 6), value: integers.u64(view, 8), size: integers.u64(view, 16)
  };

const readRel = (
  view: DataView, integers: ElfIntegerReader
): ElfSymbolicRelocationRecord | null => {
  if (view.byteLength < 16) return null;
  const info = integers.u64(view, 8);
  return { offset: integers.u64(view, 0), type: Number(info & 0xffff_ffffn),
    symbolIndex: Number(info >> 32n), addend: null };
};

const readRela = (
  view: DataView, integers: ElfIntegerReader
): ElfSymbolicRelocationRecord | null => {
  if (view.byteLength < 24) return null;
  return { ...readRel(view, integers)!, addend: integers.i64(view, 16) };
};

export const createElf64Layout = (byteOrder: ElfByteOrder): ElfBinaryLayout => {
  const integers = ELF_INTEGER_READERS[byteOrder];
  return {
    byteOrder, wordSize: 8, dynamicEntrySize: 16, symbolEntrySize: 24,
    readWord: view => view.byteLength < 8 ? null : integers.u64(view, 0),
    readDynamic: view => view.byteLength < 16 ? null :
      { tag: integers.u64(view, 0), value: integers.u64(view, 8) },
    readSymbol: view => readSymbol(view, integers),
    readSectionIndex: view => view.byteLength < ELF_SYMBOL_INDEX.BYTE_SIZE ? null : integers.u32(view, 0),
    // MIPS64 needs a dedicated codec; its little-endian r_info mixes byte orders.
    // See LLVM Elf_Rel_Impl::getRInfo rather than applying ELF64_R_SYM/TYPE blindly.
    // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/ELFTypes.h
    supportsSymbolicRelocations: machine => machine !== ELF_MACHINE_ID.MIPS,
    relocations: {
      REL: { entrySize: 16, read: view => readRel(view, integers) },
      RELA: { entrySize: 24, read: view => readRela(view, integers) }
    }
  };
};
