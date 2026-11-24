import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import type { ElfHashSource, ElfHashTable } from "./hash-types.js";
import { elfFileRange, elfVirtualExtent, elfVirtualRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { readElfHashTable } from "./hash-reader.js";
import type { ElfDynamicSymbolRange } from "./dynamic-symbol-records.js";
import { ELF_DYNAMIC_TAG, ELF_SECTION_TYPE } from "./abi-constants.js";

// SHT_HASH/DT_HASH and SHT_GNU_HASH/DT_GNU_HASH: gABI and glibc elf.h.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const hashDescriptors = {
  sysv: { sectionType: 5, tag: ELF_DYNAMIC_TAG.HASH },
  gnu: { sectionType: 0x6ffffff6, tag: 0x6ffffef5 }
} as const;

const hashSources = (elf: ElfParseResult, entries: ElfDynamicEntry[]): ElfHashSource[] => {
  const sources: ElfHashSource[] = [];
  for (const kind of ["sysv", "gnu"] as const) {
    const { sectionType, tag } = hashDescriptors[kind];
    const section = elf.sections.find(item => item.type === sectionType);
    if (section) {
      sources.push({ kind, ...(elfFileRange(section.offset, section.size, elf.fileSize) ??
        { offset: 0, size: 0 }) });
      continue;
    }
    const address = entries.find(item => item.tag === tag)?.value;
    if (address == null) continue;
    const range = elfVirtualExtent(elf.programHeaders, address, elf.fileSize);
    sources.push({ kind, ...(range ?? { offset: 0, size: 0 }) });
  }
  return sources;
};

export const parseElfHashTables = async (
  file: File, elf: ElfParseResult, entries: ElfDynamicEntry[]
): Promise<ElfHashTable[]> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const tables: ElfHashTable[] = [];
  const layout = selectElfBinaryLayout(elf);
  for (const source of hashSources(elf, entries)) tables.push(await readElfHashTable(reader, source, layout));
  return tables;
};

type HashImage = Pick<ElfParseResult, "sections" | "programHeaders"> & { file: File };

export const associatedElfHashTables = (image: HashImage, symtab: ElfDynamicSymbolRange,
  entries: ElfDynamicEntry[], tables: ElfHashTable[] | undefined): ElfHashTable[] => {
  if (!tables?.length) return [];
  const offset = BigInt(symtab.storedOffset ?? symtab.offset);
  // ELF virtual addresses are unsigned; an absent tag has no mapping.
  const symbolAddress = entries.find(entry => entry.tag === ELF_DYNAMIC_TAG.SYMTAB)?.value ?? -1n;
  const symbolRange = elfVirtualRange(image.programHeaders, symbolAddress, 1n, image.file.size);
  return tables.filter(table => {
    const { sectionType, tag } = hashDescriptors[table.kind];
    const section = image.sections.find(item => item.type === sectionType);
    if (section) {
      const linked = image.sections.find(item => item.index === section.link && item.type === ELF_SECTION_TYPE.DYNSYM);
      return linked?.offset === offset && section.offset === BigInt(table.offset);
    }
    if (symbolRange?.offset !== symtab.offset || symtab.reader) return false;
    const address = entries.find(entry => entry.tag === tag)?.value ?? -1n;
    return elfVirtualRange(image.programHeaders, address, 1n, image.file.size)?.offset === table.offset;
  });
};

// gABI 8.5: the System V chain array has one entry per dynamic symbol.
// https://gabi.xinuos.com/elf/08-dynamic.html#hash-table
export const validateElfSysvHashSymbolCount = (
  tables: ElfHashTable[], independentlyKnownCount?: number
): void => {
  // An empty GNU hash doesn't determine the number of omitted symbols.
  const gnu = tables.find(table => table.kind === "gnu" && !table.issues.length && table.chains.length);
  const count = independentlyKnownCount ??
    (gnu?.kind === "gnu" ? gnu.symbolOffset + gnu.chains.length : undefined);
  if (count === undefined) return;
  for (const table of tables) {
    if (table.kind === "sysv" && !table.issues.length && table.chains.length !== count) {
      table.issues.push(`System V hash nchain (${table.chains.length}) disagrees with the dynamic symbol count (${count}).`);
    }
  }
};
