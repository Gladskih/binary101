import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { createElfStringTableReader } from "./string-table.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { ELF_SYMBOL_INDEX } from "./abi-constants.js";
import { elfSymbolSectionFields } from "./symbol-section-index.js";
import { openElfSectionData, type ElfSectionData } from "./section-data.js";

export interface ElfStaticSymbol extends ElfRelocationSymbol {
  size: bigint;
  info: number;
  other: number;
}

export interface ElfSymbolTable {
  sectionIndex: number;
  entries: ElfStaticSymbol[];
  issues: string[];
}

// gABI 5: Elf32/64_Sym and SHT_SYMTAB_SHNDX; indices use Elf32_Word in both classes.
// https://gabi.xinuos.com/elf/05-symtab.html
const readExtendedIndex = async (
  source: ElfSectionData | null, index: number, elf: SymbolImage, issues: string[]
): Promise<number | null> => {
  const view = source && (index + 1) * 4 <= source.size
    ? await source.reader.read(source.offset + index * 4, 4) : null;
  const value = view?.byteLength === 4 ? view.getUint32(0, elf.littleEndian) : null;
  if (value != null && value >= 0xff00) return value; // SHN_LORESERVE, gABI 3.1.
  issues.push(`Symbol #${index} has an invalid SHN_XINDEX reference.`);
  return null;
};

type SymbolImage = Pick<ElfParseResult, "header" | "is64" | "littleEndian" | "sections">;

export const readElfSymbolTable = async (
  reader: FileRangeReader, elf: SymbolImage, section: ElfSectionHeader,
  cache?: Map<number, ElfRelocationSymbol>
): Promise<ElfSymbolTable> => {
  const result: ElfSymbolTable = { sectionIndex: section.index, entries: [], issues: [] };
  const layout = selectElfBinaryLayout(elf);
  if (section.entsize !== BigInt(layout.symbolEntrySize)) {
    result.issues.push("Symbol table has an invalid entry size.");
    return result;
  }
  const source = await openElfSectionData(reader, section, elf, result.issues);
  if (!source) return result;
  if (source.size % layout.symbolEntrySize) result.issues.push("Symbol table size is not aligned.");
  const strings = elf.sections.find(item => item.index === section.link && item.type === 3);
  const names = strings ? await openElfSectionData(reader, strings, elf, result.issues) : null;
  const readName = createElfStringTableReader(names?.reader ?? reader, names, result.issues);
  const extended = elf.sections.find(item => item.type === 18 && item.link === section.index);
  const indices = extended?.entsize === 4n ? await openElfSectionData(reader, extended, elf, result.issues) : null;
  const count = Math.floor(source.size / layout.symbolEntrySize);
  for (let index = 0; index < count; index += 1) {
    const offset = source.offset + index * layout.symbolEntrySize;
    const record = layout.readSymbol(await source.reader.read(offset, layout.symbolEntrySize));
    if (!record) {
      result.issues.push(`Symbol #${index} is truncated.`);
      break;
    }
    const extendedIndex = record.sectionIndex === ELF_SYMBOL_INDEX.XINDEX
      ? await readExtendedIndex(indices, index, elf, result.issues) : null;
    const symbol = { name: await readName(record.nameOffset) ?? "", value: record.value,
      ...elfSymbolSectionFields(record.sectionIndex, extendedIndex) };
    if (source.reader === reader) cache?.set(offset, symbol);
    result.entries.push({ ...symbol, size: record.size, info: record.info, other: record.other });
  }
  return result;
};

export const parseElfSymbolTables = async (
  file: File, elf: ElfParseResult, cache = new Map<number, ElfRelocationSymbol>()
): Promise<ElfSymbolTable[]> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const tables: ElfSymbolTable[] = [];
  for (const section of elf.sections.filter(item => item.type === 2)) {
    tables.push(await readElfSymbolTable(reader, elf, section, cache));
  }
  return tables;
};
