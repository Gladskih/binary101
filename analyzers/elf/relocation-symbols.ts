import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocationSymbol, ElfRelocationTable } from "./relocation-types.js";
import { elfFileRange, elfVirtualRange, readElfRelocationString } from
  "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { ELF_DYNAMIC_TAG as DT, ELF_SECTION_TYPE as SECTION, ELF_SYMBOL_INDEX } from "./abi-constants.js";
import { declaredDynamicSymbolRange } from "./dynsym-range.js";
import { elfSymbolSectionFields } from "./symbol-section-index.js";
import { ELF_SECTION_COMPRESSED, hasCompressedSectionAt } from "./section-data.js";
import { readElfSymbolTable, type ElfSymbolTable } from "./symbol-tables.js";
import { elfVirtualDataRange, openElfDataRange } from "./virtual-data.js";

// gABI Symbol table: Elf32_Sym / Elf64_Sym, SHN_XINDEX, SHT_SYMTAB_SHNDX.
// https://gabi.xinuos.com/elf/05-symtab.html
type SymbolLocation = {
  offset: number;
  strings: { offset: number; size: number; reader?: FileRangeReader } | null;
};

const locateSectionSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  index: number, stride: number, tags: Map<number, bigint>, runtimeStrings: SymbolLocation["strings"]
): SymbolLocation | null => {
  const section = elf.sections.find(item => item.index === table.symbolTableIndex);
  if (!section || (section.type !== SECTION.SYMTAB && section.type !== SECTION.DYNSYM) ||
    section.entsize !== BigInt(stride) ||
    BigInt(index + 1) * BigInt(stride) > section.size) return null;
  const range = elfFileRange(section.offset + BigInt(index * stride), BigInt(stride), reader.size);
  if (!range) return null;
  if (section.type === SECTION.DYNSYM) {
    // ELF virtual addresses are unsigned; an absent tag has no mapping.
    const runtime = elfVirtualRange(elf.programHeaders, tags.get(DT.SYMTAB) ?? -1n, 1n, reader.size);
    if (runtimeStrings && runtime?.offset === Number(section.offset)) {
      return { offset: range.offset, strings: runtimeStrings };
    }
  }
  const strings = elf.sections.find(item => item.index === section.link && item.type === SECTION.STRTAB);
  return { offset: range.offset,
    strings: strings ? elfFileRange(strings.offset, strings.size, reader.size) : null };
};

const dynamicStrings = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>
): SymbolLocation["strings"] => {
  if (!tags.has(DT.STRTAB) || !tags.has(DT.STRSZ)) return null;
  const range = elfVirtualDataRange(elf.programHeaders, tags.get(DT.STRTAB)!, tags.get(DT.STRSZ)!, reader.size);
  return range && !hasCompressedSectionAt(elf.sections, SECTION.STRTAB, range.offset)
    ? openElfDataRange(reader, range) : null;
};

const dynamicSymbolSize = (reader: FileRangeReader, elf: ElfRelocationImage,
  tags: Map<number, bigint>, stride: number, issues: string[]): bigint | null => {
  const address = tags.get(DT.SYMTAB);
  if (address == null) return null;
  const section = elf.sections.find(section => section.type === SECTION.DYNSYM &&
    section.addr === address);
  if (section) return section.entsize === BigInt(stride) && !(section.flags & ELF_SECTION_COMPRESSED)
    ? section.size : 0n;
  const declaredSize = tags.get(DT.SYMTABSZ);
  if (declaredSize != null) return BigInt(declaredDynamicSymbolRange(
    elf.programHeaders, address, declaredSize, stride, reader.size, issues)?.size ?? 0);
  // Reuse the count already established from dynamic hashes; don't scan them again.
  // A section-derived count is only applicable to its own table (checked above).
  if (!elf.sections.some(section => section.type === SECTION.DYNSYM) &&
    elf.dynSymbols && !elf.dynSymbols.issues.length) return BigInt(elf.dynSymbols.total * stride);
  return null;
};

const withinDynamicSymbols = (size: bigint | null, index: number, stride: number): boolean =>
  size == null || (size >= 0n && size % BigInt(stride) === 0n &&
  BigInt(index + 1) * BigInt(stride) <= size);

const locateDynamicSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>, index: number,
  stride: number, size: bigint | null, strings: SymbolLocation["strings"]
): SymbolLocation | null => {
  const address = tags.get(DT.SYMTAB);
  if (address == null || tags.get(DT.SYMENT) !== BigInt(stride)) return null;
  if (!withinDynamicSymbols(size, index, stride)) return null;
  const stringsAddress = tags.get(DT.STRTAB);
  if (stringsAddress != null && stringsAddress > address &&
    address + BigInt(index + 1) * BigInt(stride) > stringsAddress) return null;
  const range = elfVirtualRange(elf.programHeaders, address + BigInt(index * stride),
    BigInt(stride), reader.size);
  // In sectionless files a relocation itself supplies the symbol index. The complete
  // entry must lie in a file-backed PT_LOAD; never infer a table extending to EOF.
  return range ? { offset: range.offset, strings } : null;
};

const locateSymbol = (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  tags: Map<number, bigint>, index: number, stride: number, dynamicSize: bigint | null,
  strings: SymbolLocation["strings"]
): SymbolLocation | null => {
  if (!Number.isSafeInteger(index) || index < 0 || index > ELF_SYMBOL_INDEX.MAX) return null;
  return table.symbolTableIndex != null ? locateSectionSymbol(reader, elf, table, index, stride, tags, strings) :
    locateDynamicSymbol(reader, elf, tags, index, stride, dynamicSize, strings);
};

const extendedSectionIndex = async (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  index: number, issues: string[], layout: ElfBinaryLayout, tags: Map<number, bigint>
): Promise<number | null> => {
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
  return null;
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
  const extendedIndex = record.sectionIndex === ELF_SYMBOL_INDEX.XINDEX
    ? await extendedSectionIndex(reader, elf, table, index, issues, layout, tags) : null;
  const strings = location.strings;
  let name = "";
  if (!strings || nameOffset >= strings.size) {
    issues.push(`Relocation symbol #${index} has an invalid string table offset.`);
  } else {
    name = await readElfRelocationString(strings.reader ?? reader, BigInt(strings.offset + nameOffset),
      BigInt(strings.size - nameOffset), issues);
  }
  return { name, value: record.value, ...elfSymbolSectionFields(record.sectionIndex, extendedIndex) };
};

const compressedSymbolTables = (elf: ElfRelocationImage) => {
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  const extended = new Set(elf.sections.filter(section => section.type === SECTION.SYMTAB_SHNDX &&
    (section.flags & ELF_SECTION_COMPRESSED)).map(section => section.link));
  return new Map(elf.sections.filter(section => {
    if (section.type !== SECTION.SYMTAB && section.type !== SECTION.DYNSYM) return false;
    const strings = sections.get(section.link);
    return ((section.flags | (strings?.flags ?? 0n)) & ELF_SECTION_COMPRESSED) || extended.has(section.index);
  }).map(section => [section.index, section]));
};

const createCompressedSymbolReader = (reader: FileRangeReader, elf: ElfRelocationImage, issues: string[]) => {
  const sections = compressedSymbolTables(elf);
  const decoded = new Map<number, Promise<ElfSymbolTable>>(elf.symbolTables?.map(table =>
    [table.sectionIndex, Promise.resolve(table)]));
  const decode = async (index: number): Promise<ElfSymbolTable> => {
    const table = await readElfSymbolTable(reader, elf, sections.get(index)!);
    issues.push(...table.issues);
    return table;
  };
  return {
    sections,
    read: async (index: number, symbolIndex: number): Promise<ElfRelocationSymbol | null> => {
      if (!decoded.has(index)) decoded.set(index, decode(index));
      const symbol = (await decoded.get(index)!).entries[symbolIndex];
      if (!symbol) {
        issues.push(`Relocation symbol #${symbolIndex} is outside its symbol table or PT_LOAD.`);
        return null;
      }
      const { name, value, sectionIndex, rawSectionIndex } = symbol;
      return { name, value, sectionIndex, ...(rawSectionIndex != null && { rawSectionIndex }) };
    }
  };
};

export const createElfRelocationSymbolReader = (
  reader: FileRangeReader, elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[],
  parsedSymbols: Map<number, ElfRelocationSymbol> = new Map(), layout = selectElfBinaryLayout(elf)
): ((table: ElfRelocationTable, index: number) => Promise<ElfRelocationSymbol | null>) => {
  // Cache by physical symbol record, so aliases of .dynsym share decoded names.
  const cache = new Map<number, ElfRelocationSymbol | null>();
  const compressed = createCompressedSymbolReader(reader, elf, issues);
  const dynamicSize = dynamicSymbolSize(reader, elf, tags, layout.symbolEntrySize, issues);
  const strings = dynamicStrings(reader, elf, tags);
  let reportedBoundary = false;
  return async (table, index) => {
    if (table.symbolTableIndex != null && compressed.sections.has(table.symbolTableIndex)) {
      return compressed.read(table.symbolTableIndex, index);
    }
    const location = locateSymbol(reader, elf, table, tags, index, layout.symbolEntrySize, dynamicSize, strings);
    if (!location) {
      issues.push(`Relocation symbol #${index} is outside its symbol table or PT_LOAD.`);
      return null;
    }
    if (table.symbolTableIndex == null && !reportedBoundary && dynamicSize == null) {
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
