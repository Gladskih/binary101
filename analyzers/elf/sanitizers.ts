import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { SanitizerDependency, SanitizerEvidence, SanitizerSymbol } from "../sanitizers/types.js";
import { analyzeSanitizerEvidence } from "../sanitizers/evidence.js";
import { SANITIZER_ABI_SYMBOLS } from "../sanitizers/abi-catalog.js";

const executableSections = (elf: ElfParseResult): ReadonlyMap<number, ElfSectionHeader> =>
  new Map(elf.sections.filter(section =>
    // SHT_PROGBITS=1, SHF_EXECINSTR=4 (gABI section header specification).
    section.type === 1 && (section.flags & 4n) !== 0n && section.offset >= 0n &&
    section.size > 0n && section.offset + section.size <= BigInt(elf.fileSize)
  ).map(section => [section.index, section]));

const definitionIsMapped = (elf: ElfParseResult, sections: ReadonlyMap<number, ElfSectionHeader>,
  sectionIndex: number, value: bigint): boolean => {
  const section = sections.get(sectionIndex);
  if (section) {
    // ET_REL=1: st_value is a section offset, otherwise a virtual address (gABI 5).
    const offset = elf.header.type === 1 ? value : value - section.addr;
    return offset >= 0n && offset < section.size;
  }
  // Stripped ELF files may have no section headers; use file-backed executable PT_LOADs.
  return elf.sections.length === 0 && sectionIndex > 0 && sectionIndex < 0xff00 &&
    elf.programHeaders.some(segment => segment.type === 1 && (segment.flags & 1) !== 0 &&
      segment.offset >= 0n && segment.offset + segment.filesz <= BigInt(elf.fileSize) &&
      value >= segment.vaddr && value - segment.vaddr < segment.filesz);
};

const elfSymbol = (elf: ElfParseResult, sections: ReadonlyMap<number, ElfSectionHeader>,
  name: string, info: number, sectionIndex: number, value: bigint,
  source: string): SanitizerSymbol | null => {
  if (!SANITIZER_ABI_SYMBOLS.has(name)) return null;
  // STT_NOTYPE=0, STT_FUNC=2; STB_LOCAL/GLOBAL/WEAK=0/1/2 (gABI 5).
  // https://gabi.xinuos.com/elf/05-symtab.html
  // Undefined local symbols are not loader references.
  if (sectionIndex === 0 && [0, 2].includes(info & 15) && [1, 2].includes(info >> 4)) {
    return { name, source, kind: "reference" };
  }
  return (info & 15) === 2 && [0, 1, 2].includes(info >> 4) &&
    definitionIsMapped(elf, sections, sectionIndex, value)
    ? { name, source, kind: "definition" } : null;
};

function* elfSymbols(elf: ElfParseResult): IterableIterator<SanitizerSymbol> {
  const sections = executableSections(elf);
  if (elf.dynSymbols && !elf.dynSymbols.issues.length) {
    for (const records of [elf.dynSymbols.importSymbols, elf.dynSymbols.exportSymbols]) {
      for (const record of records) {
        const symbol = elfSymbol(elf, sections, record.name, record.bind * 16 + record.type,
          record.shndx, record.value, "ELF dynamic symbols");
        if (symbol) yield symbol;
      }
    }
  }
  for (const table of elf.symbolTables ?? []) {
    if (table.issues.length) continue;
    for (const record of table.entries) {
      const symbol = elfSymbol(elf, sections, record.name, record.info,
        record.sectionIndex, record.value, `ELF symbol table #${table.sectionIndex}`);
      if (symbol) yield symbol;
    }
  }
}

const elfDependencies = (elf: ElfParseResult): SanitizerDependency[] =>
  elf.dynamic && !elf.dynamic.issues.length
    ? elf.dynamic.needed.map(name => ({ name, source: "ELF DT_NEEDED" })) : [];

export const analyzeElfSanitizers = (elf: ElfParseResult): SanitizerEvidence[] => {
  const evidence = analyzeSanitizerEvidence(elfDependencies(elf), elfSymbols(elf));
  // Go's build-info framing is already validated by parseGoBuildInfo. Match a whole setting,
  // never an arbitrary string containing -race (debug/buildinfo and runtime/debug/mod.go).
  if (elf.goBuildInfo?.moduleInfo.split("\n").includes("build\t-race=true")) {
    evidence.push({ tool: "Go race detector", kind: "build-setting",
      source: "Go build information", name: "-race=true" });
  }
  return evidence;
};
