import { ELF_INTEGER_READERS, type ElfIntegerReader } from "./byte-order.js";
import type { ElfBinaryLayout, ElfByteOrder, ElfSymbolRecord,
  ElfSymbolicRelocationRecord } from "./binary-layout-types.js";
import { ELF_SYMBOL_INDEX } from "./abi-constants.js";

// Fixed Elf32 layouts, field byte offsets and ELF32_R_SYM/TYPE masks:
// https://gabi.xinuos.com/elf/05-symtab.html (Elf32_Sym, 16 bytes)
// https://gabi.xinuos.com/elf/06-reloc.html (Elf32_Rel, 8; Elf32_Rela, 12)
// https://gabi.xinuos.com/elf/08-dynamic.html (Elf32_Dyn, 8)
const readSymbol = (view: DataView, integers: ElfIntegerReader): ElfSymbolRecord | null =>
  view.byteLength < 16 ? null : {
    nameOffset: integers.u32(view, 0), value: BigInt(integers.u32(view, 4)),
    size: BigInt(integers.u32(view, 8)), info: view.getUint8(12), other: view.getUint8(13),
    sectionIndex: integers.u16(view, 14)
  };

const readRel = (
  view: DataView, integers: ElfIntegerReader
): ElfSymbolicRelocationRecord | null => {
  if (view.byteLength < 8) return null;
  const info = integers.u32(view, 4);
  return { offset: BigInt(integers.u32(view, 0)), type: info & 0xff,
    symbolIndex: info >>> 8, addend: null };
};

const readRela = (
  view: DataView, integers: ElfIntegerReader
): ElfSymbolicRelocationRecord | null => {
  if (view.byteLength < 12) return null;
  return { ...readRel(view, integers)!, addend: BigInt(integers.i32(view, 8)) };
};

export const createElf32Layout = (byteOrder: ElfByteOrder): ElfBinaryLayout => {
  const integers = ELF_INTEGER_READERS[byteOrder];
  return {
    byteOrder, wordSize: 4, dynamicEntrySize: 8, symbolEntrySize: 16,
    readWord: view => view.byteLength < 4 ? null : BigInt(integers.u32(view, 0)),
    readDynamic: view => view.byteLength < 8 ? null :
      { tag: BigInt(integers.u32(view, 0)), value: BigInt(integers.u32(view, 4)) },
    readSymbol: view => readSymbol(view, integers),
    readSectionIndex: view => view.byteLength < ELF_SYMBOL_INDEX.BYTE_SIZE ? null : integers.u32(view, 0),
    supportsSymbolicRelocations: _machine => true,
    relocations: {
      REL: { entrySize: 8, read: view => readRel(view, integers) },
      RELA: { entrySize: 12, read: view => readRela(view, integers) }
    }
  };
};
