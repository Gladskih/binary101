import { ELF_INTEGER_READERS } from "./byte-order.js";
import type { ElfByteOrder, ElfFileHeaderRecord } from "./binary-layout-types.js";

// Elf32_Ehdr and Elf64_Ehdr share field order, with three class-sized fields.
// https://gabi.xinuos.com/elf/02-eheader.html
const EI_NIDENT = 16;

const headerFields = <NumberField, AddressField>(
  half: () => NumberField, word: () => NumberField, address: () => AddressField
) => ({
  type: half(), machine: half(), version: word(), entry: address(),
  phoff: address(), shoff: address(), flags: word(), ehsize: half(),
  phentsize: half(), phnum: half(), shentsize: half(), shnum: half(), shstrndx: half()
});

export const readElfHeaderRecord = (
  view: DataView, order: ElfByteOrder, size: 4 | 8
): ElfFileHeaderRecord | null => {
  // Three 4-byte words (type+machine, version, flags) and six 2-byte fields.
  if (view.byteLength < EI_NIDENT + 24 + size * 3) return null;
  const integers = ELF_INTEGER_READERS[order];
  let offset = EI_NIDENT;
  const take = <T>(width: number, read: (view: DataView, offset: number) => T): T => {
    const start = offset;
    offset += width;
    return read(view, start);
  };
  return headerFields(() => take(2, integers.u16), () => take(4, integers.u32),
    size === 4 ? () => BigInt(take(4, integers.u32)) : () => take(8, integers.u64));
};

export const readElfHeaderPrefix = (view: DataView, order: ElfByteOrder, size: 4 | 8) => {
  const integers = ELF_INTEGER_READERS[order];
  let offset = EI_NIDENT;
  const take = <T>(width: number, read: (view: DataView, offset: number) => T): T | undefined => {
    const start = offset;
    offset += width;
    return offset <= view.byteLength ? read(view, start) : undefined;
  };
  const read32 = (source: DataView, start: number): bigint => BigInt(integers.u32(source, start));
  return headerFields(() => take(2, integers.u16), () => take(4, integers.u32),
    size === 4 ? () => take(4, read32) : () => take(8, integers.u64));
};
