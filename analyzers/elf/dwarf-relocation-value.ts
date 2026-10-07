import type { ElfRelocation, ElfRelocationImage } from "./relocation-types.js";
import type { ElfSectionHeader } from "./types.js";
import type { ElfDwarfRelocationKind } from "./dwarf-relocation-types.js";

// gABI 6 / 5: ET_REL symbols are section-relative; SHN_ABS is absolute.
// https://gabi.xinuos.com/elf/06-reloc.html
const symbolValue = (entry: ElfRelocation, elf: ElfRelocationImage,
  sections: Map<number, ElfSectionHeader>): bigint | string => {
  if (entry.symbolIndex === 0) return 0n;
  const symbol = entry.symbol;
  if (!symbol || !symbol.sectionIndex) return "Unresolved DWARF relocation symbol";
  if (symbol.sectionIndex === 0xfff1) return symbol.value; // SHN_ABS, gABI 5.
  const section = sections.get(symbol.sectionIndex);
  if (!section) return "DWARF relocation symbol has an unavailable section";
  return symbol.value + (elf.header.type === 1 ? section.addr : 0n);
};

const fits = (value: bigint, kind: ElfDwarfRelocationKind): boolean => {
  if (kind.overflow === "truncate") return true;
  const bits = BigInt(kind.width * 8);
  const minimum = kind.overflow === "unsigned" ? 0n : -(1n << (bits - 1n));
  const maximum = 1n << (bits - (kind.overflow === "signed" ? 1n : 0n));
  return value >= minimum && value < maximum;
};

export const elfDwarfRelocationValue = (entry: ElfRelocation, kind: ElfDwarfRelocationKind,
  elf: ElfRelocationImage, sections: Map<number, ElfSectionHeader>, place: bigint,
  original: bigint, current: bigint): bigint | string => {
  const symbol = symbolValue(entry, elf, sections);
  if (typeof symbol === "string") return symbol;
  const addend = entry.addend ?? BigInt.asIntN(kind.width * 8, original);
  const value = relocationOperation(symbol + addend, current, place, kind.operation);
  return fits(value, kind) ? BigInt.asUintN(kind.width * 8, value) : "DWARF relocation overflow";
};

const relocationOperation = (value: bigint, current: bigint, place: bigint,
  operation: ElfDwarfRelocationKind["operation"]): bigint => {
  if (operation === "relative") return value - place;
  if (operation === "add") return current + value;
  return operation === "subtract" ? current - value : value;
};
