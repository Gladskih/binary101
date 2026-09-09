import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { elfFileRange } from "./relocation-reader.js";
import { createElfStringTableReader } from "./string-table.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";

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
  reader: FileRangeReader, section: ElfSectionHeader | undefined,
  index: number, elf: ElfParseResult, issues: string[]
): Promise<number> => {
  const range = section?.entsize === 4n && BigInt(index + 1) * 4n <= section.size
    ? elfFileRange(section.offset + BigInt(index) * 4n, 4n, reader.size) : null;
  const view = range ? await reader.read(range.offset, 4) : null;
  if (view?.byteLength === 4) return view.getUint32(0, elf.littleEndian);
  issues.push(`Symbol #${index} has an invalid SHN_XINDEX reference.`);
  return 0xffff;
};

const staticTableRange = (
  section: ElfSectionHeader, stride: number, fileSize: number, issues: string[]
): { offset: number; size: number } | null => {
  if (section.entsize !== BigInt(stride)) {
    issues.push("Symbol table has an invalid entry size.");
    return null;
  }
  const range = elfFileRange(section.offset, section.size, fileSize);
  if (!range) {
    issues.push("Symbol table is truncated or outside the file.");
    return null;
  }
  if (range.size % stride) issues.push("Symbol table size is not aligned.");
  // Resource policy: bound retained symbols to one million entries per table.
  if (range.size > stride * 1000000) {
    issues.push("Symbol table exceeds the 1000000 entry resource limit.");
  }
  return { offset: range.offset, size: Math.min(range.size, stride * 1000000) };
};

const readStaticTable = async (
  reader: FileRangeReader, elf: ElfParseResult, section: ElfSectionHeader,
  cache: Map<number, ElfRelocationSymbol>
): Promise<ElfSymbolTable> => {
  const result: ElfSymbolTable = { sectionIndex: section.index, entries: [], issues: [] };
  const layout = selectElfBinaryLayout(elf);
  const range = staticTableRange(section, layout.symbolEntrySize, reader.size, result.issues);
  if (!range) return result;
  const strings = elf.sections.find(item => item.index === section.link && item.type === 3);
  const readName = createElfStringTableReader(reader,
    strings ? elfFileRange(strings.offset, strings.size, reader.size) : null, result.issues);
  const extended = elf.sections.find(item => item.type === 18 && item.link === section.index);
  const count = Math.floor(range.size / layout.symbolEntrySize);
  for (let index = 0; index < count; index += 1) {
    const offset = range.offset + index * layout.symbolEntrySize;
    const record = layout.readSymbol(await reader.read(offset, layout.symbolEntrySize));
    if (!record) {
      result.issues.push(`Symbol #${index} is truncated.`);
      break;
    }
    const symbol = { name: await readName(record.nameOffset), value: record.value,
      sectionIndex: record.sectionIndex === 0xffff
        ? await readExtendedIndex(reader, extended, index, elf, result.issues) : record.sectionIndex };
    cache.set(offset, symbol);
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
    tables.push(await readStaticTable(reader, elf, section, cache));
  }
  return tables;
};
