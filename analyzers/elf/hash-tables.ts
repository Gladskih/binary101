import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import type { ElfHashSource, ElfHashTable } from "./hash-types.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { readElfHashTable } from "./hash-reader.js";

// SHT_HASH/DT_HASH and SHT_GNU_HASH/DT_GNU_HASH: gABI and glibc elf.h.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const hashSources = (elf: ElfParseResult, entries: ElfDynamicEntry[]): ElfHashSource[] => {
  const sources: ElfHashSource[] = [];
  for (const [kind, type, tag] of [["sysv", 5, 4], ["gnu", 0x6ffffff6, 0x6ffffef5]] as const) {
    const section = elf.sections.find(item => item.type === type);
    if (section) {
      sources.push({ kind, ...(elfFileRange(section.offset, section.size, elf.fileSize) ??
        { offset: 0, size: 0 }) });
      continue;
    }
    const address = entries.find(item => item.tag === tag)?.value;
    if (address == null) continue;
    const segment = elf.programHeaders.find(item => item.type === 1 &&
      address >= item.vaddr && address < item.vaddr + item.filesz);
    const range = segment ? elfVirtualRange(elf.programHeaders, address,
      segment.vaddr + segment.filesz - address, elf.fileSize) : null;
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
