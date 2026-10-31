import { detectEmbeddedResources } from "../embedded-resources/detect.js";
import type { ResourceReference, ResourceSymbol } from "../embedded-resources/types.js";
import type { ElfParseResult } from "./types.js";
import type { ElfStaticSymbol } from "./symbol-tables.js";
import type { ElfSectionHeader } from "./types.js";

const symbolRange = (elf: ElfParseResult, symbol: ElfStaticSymbol, section: ElfSectionHeader | undefined) => {
  if (!section || section.type === 8 || (section.flags & 0x800n) !== 0n || symbol.size === 0n) return null;
  const relative = symbol.value - (elf.header.type === 1 ? 0n : section.addr);
  if (relative < 0n || relative + symbol.size > section.size) return null;
  return { offset: Number(section.offset + relative), size: Number(symbol.size) };
};

const resourceSymbols = (elf: ElfParseResult): ResourceSymbol[] => {
  const result: ResourceSymbol[] = [];
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  for (const table of elf.symbolTables ?? []) {
    let scope = `ELF symbol table #${table.sectionIndex}`;
    for (const [index, symbol] of table.entries.entries()) {
      if ((symbol.info & 15) === 4) scope = `ELF table #${table.sectionIndex}, file symbol #${index}`;
      if (!symbol.name.includes("qt_resource_")) continue;
      const range = symbolRange(elf, symbol, sections.get(symbol.sectionIndex));
      if (range) result.push({ name: symbol.name, scope, ...range });
    }
  }
  return result;
};

const relocationReferences = (elf: ElfParseResult): ResourceReference[] => {
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  return (elf.relocations?.entries ?? []).flatMap(relocation => {
    const symbol = relocation.symbol;
    if (!symbol) return [];
    const section = sections.get(symbol.sectionIndex);
    if (!section || section.type === 8 || (section.flags & 0x800n) !== 0n) return [];
    const relative = symbol.value - (elf.header.type === 1 ? 0n : section.addr);
    if (relative < 0n || relative >= section.size) return [];
    return [{ targetOffset: Number(section.offset + relative),
      description: `ELF relocation at ${relocation.recordOffset} names ${symbol.name}` }];
  });
};

export const analyzeElfEmbeddedResources = (file: File, elf: ElfParseResult) =>
  detectEmbeddedResources(file, elf.sections.length ? elf.sections
    .filter(section => section.type !== 8 && (section.flags & 0x800n) === 0n)
    .map(section => ({ name: section.name ?? "", offset: Number(section.offset), size: Number(section.size) })) :
    elf.programHeaders.filter(segment => segment.type === 1).map(segment => ({
      name: `PT_LOAD #${segment.index}`, offset: Number(segment.offset), size: Number(segment.filesz)
    })), resourceSymbols(elf), relocationReferences(elf));
