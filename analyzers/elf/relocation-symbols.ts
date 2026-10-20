import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocationSymbol, ElfRelocationTable } from "./relocation-types.js";
import { elfFileRange, elfVirtualRange, readElfRelocationString } from
  "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { ELF_DYNAMIC_TAG as DT, ELF_SECTION_TYPE as SECTION, ELF_SYMBOL_INDEX } from "./abi-constants.js";

// gABI Symbol table: Elf32_Sym / Elf64_Sym, SHN_XINDEX, SHT_SYMTAB_SHNDX.
// https://gabi.xinuos.com/elf/05-symtab.html
type SymbolLocation = {
  offset: number;
  strings: { offset: number; size: number } | null;
};

const locateSectionSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  index: number, stride: number
): SymbolLocation | null => {
  const section = elf.sections.find(item => item.index === table.symbolTableIndex);
  if (!section || (section.type !== SECTION.SYMTAB && section.type !== SECTION.DYNSYM) ||
    section.entsize !== BigInt(stride) ||
    BigInt(index + 1) * BigInt(stride) > section.size) return null;
  const range = elfFileRange(section.offset + BigInt(index * stride), BigInt(stride), reader.size);
  const strings = elf.sections.find(item => item.index === section.link && item.type === SECTION.STRTAB);
  return range ? { offset: range.offset,
    strings: strings ? elfFileRange(strings.offset, strings.size, reader.size) : null } : null;
};

const dynamicStrings = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>
): { offset: number; size: number } | null =>
  tags.has(DT.STRTAB) && tags.has(DT.STRSZ)
    ? elfVirtualRange(elf.programHeaders, tags.get(DT.STRTAB)!, tags.get(DT.STRSZ)!, reader.size) : null;

const dynamicSymbolSize = (elf: ElfRelocationImage, tags: Map<number, bigint>,
  stride: number): bigint | null => {
  const section = elf.sections.find(section => section.type === SECTION.DYNSYM &&
    section.addr === tags.get(DT.SYMTAB));
  if (section) return section.entsize === BigInt(stride) ? section.size : 0n;
  if (tags.has(DT.SYMTABSZ)) return tags.get(DT.SYMTABSZ)!;
  // Reuse the count already established from dynamic hashes; don't scan them again.
  // A section-derived count is only applicable to its own table (checked above).
  if (!elf.sections.some(section => section.type === SECTION.DYNSYM) &&
    elf.dynSymbols && !elf.dynSymbols.issues.length) return BigInt(elf.dynSymbols.total * stride);
  return null;
};

const withinDynamicSymbols = (elf: ElfRelocationImage, tags: Map<number, bigint>,
  index: number, stride: number): boolean => {
  const size = dynamicSymbolSize(elf, tags, stride);
  return size == null || (size >= 0n && size % BigInt(stride) === 0n &&
    BigInt(index + 1) * BigInt(stride) <= size);
};

const locateDynamicSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>, index: number,
  stride: number
): SymbolLocation | null => {
  const address = tags.get(DT.SYMTAB);
  if (address == null || tags.get(DT.SYMENT) !== BigInt(stride)) return null;
  if (!withinDynamicSymbols(elf, tags, index, stride)) return null;
  const stringsAddress = tags.get(DT.STRTAB);
  if (stringsAddress != null && stringsAddress > address &&
    address + BigInt(index + 1) * BigInt(stride) > stringsAddress) return null;
  const range = elfVirtualRange(elf.programHeaders, address + BigInt(index * stride),
    BigInt(stride), reader.size);
  // In sectionless files a relocation itself supplies the symbol index. The complete
  // entry must lie in a file-backed PT_LOAD; never infer a table extending to EOF.
  return range ? { offset: range.offset, strings: dynamicStrings(reader, elf, tags) } : null;
};

const locateSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  tags: Map<number, bigint>, index: number, stride: number
): SymbolLocation | null => {
  if (!Number.isSafeInteger(index) || index < 0 || index > ELF_SYMBOL_INDEX.MAX) return null;
  return table.symbolTableIndex != null ? locateSectionSymbol(reader, elf, table, index, stride) :
    locateDynamicSymbol(reader, elf, tags, index, stride);
};

const extendedSectionIndex = async (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  index: number, issues: string[], layout: ElfBinaryLayout, tags: Map<number, bigint>
): Promise<number> => {
  const section = elf.sections.find(item => item.type === SECTION.SYMTAB_SHNDX && item.link === table.symbolTableIndex);
  const width = BigInt(ELF_SYMBOL_INDEX.BYTE_SIZE);
  const address = tags.get(DT.SYMTAB_SHNDX);
  const range = table.symbolTableIndex == null && address != null ?
    elfVirtualRange(elf.programHeaders, address + BigInt(index) * width, width, reader.size) :
    section && section.entsize === width && BigInt(index + 1) * width <= section.size
      ? elfFileRange(section.offset + BigInt(index) * width, width, reader.size) : null;
  const value = range ? layout.readSectionIndex(await reader.read(range.offset, ELF_SYMBOL_INDEX.BYTE_SIZE)) : null;
  if (value != null && value >= 0xff00) return value; // gABI SHN_LORESERVE.
  issues.push(`Relocation symbol #${index} has an invalid SHN_XINDEX reference.`);
  return ELF_SYMBOL_INDEX.XINDEX;
};

const readSymbol = async (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  location: SymbolLocation, index: number, issues: string[], layout: ElfBinaryLayout, tags: Map<number, bigint>
): Promise<ElfRelocationSymbol | null> => {
  const record = layout.readSymbol(await reader.read(location.offset, layout.symbolEntrySize));
  if (!record) {
    issues.push(`Relocation symbol #${index} is truncated.`);
    return null;
  }
  const nameOffset = record.nameOffset;
  let sectionIndex = record.sectionIndex;
  if (sectionIndex === ELF_SYMBOL_INDEX.XINDEX) {
    sectionIndex = await extendedSectionIndex(reader, elf, table, index, issues, layout, tags);
  }
  const strings = location.strings;
  let name = "";
  if (!strings || nameOffset >= strings.size) {
    issues.push(`Relocation symbol #${index} has an invalid string table offset.`);
  } else {
    name = await readElfRelocationString(reader, BigInt(strings.offset + nameOffset),
      BigInt(strings.size - nameOffset), issues);
  }
  return { name, value: record.value, sectionIndex };
};

export const createElfRelocationSymbolReader = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[],
  parsedSymbols: Map<number, ElfRelocationSymbol> = new Map(), layout = selectElfBinaryLayout(elf)
): ((table: ElfRelocationTable, index: number) => Promise<ElfRelocationSymbol | null>) => {
  // Cache by physical symbol record, so aliases of .dynsym share decoded names.
  const cache = new Map<number, ElfRelocationSymbol | null>();
  let reportedBoundary = false;
  return async (table, index) => {
    const location = locateSymbol(reader, elf, table, tags, index, layout.symbolEntrySize);
    if (!location) {
      issues.push(`Relocation symbol #${index} is outside its symbol table or PT_LOAD.`);
      return null;
    }
    if (table.symbolTableIndex == null && !reportedBoundary &&
      dynamicSymbolSize(elf, tags, layout.symbolEntrySize) == null) {
      issues.push("ELF dynamic symbol table has no established size; references are only bounded by PT_LOAD and DT_STRTAB.");
      reportedBoundary = true;
    }
    if (cache.has(location.offset)) return cache.get(location.offset)!;
    if (location.strings && parsedSymbols.has(location.offset)) return parsedSymbols.get(location.offset)!;
    const symbol = await readSymbol(reader, elf, table, location, index, issues, layout, tags);
    cache.set(location.offset, symbol);
    return symbol;
  };
};
