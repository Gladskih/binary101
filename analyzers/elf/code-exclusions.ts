import type { CodeExclusion } from "../code-exclusions.js";
import type { AnalyzeElfInstructionSetOptions } from "./disassembly-types.js";
import { isElfSymbolData } from "./symbol-names.js";
import { elfVirtualRange } from "./relocation-reader.js";
import type { ElfSectionHeader } from "./types.js";

const hasDataAddress = (
  section: ElfSectionHeader, opts: AnalyzeElfInstructionSetOptions
): boolean => {
  // gABI 3: SHF_ALLOC = 2, SHF_EXECINSTR = 4. ET_REL offsets belong to their section.
  // https://gabi.xinuos.com/elf/03-sheader.html
  if ((section.flags & 2n) === 0n) return false;
  if (opts.fileType !== 1) return true;
  if ((section.flags & 4n) === 0n) return false;
  // The ISA walker uses addresses; overlapping ET_REL sections have no unique address.
  return !opts.sections.some(other => other.index !== section.index &&
    (other.flags & 4n) !== 0n && other.addr < section.addr + section.size &&
    section.addr < other.addr + other.size);
};

const symbolRange = (
  symbol: { name: string; value: bigint; size: bigint }, sectionIndex: number, type: number,
  opts: AnalyzeElfInstructionSetOptions, fileSize: number, issues: string[]
): CodeExclusion | null => {
  // gABI 5: UNDEF/COMMON/ABS are not allocated section definitions; TLS values are offsets.
  // https://gabi.xinuos.com/elf/05-symtab.html
  if (sectionIndex === 0 || (sectionIndex >= 0xff00 && sectionIndex <= 0xffff) || type === 6 ||
    (type !== 1 && type !== 5 && (type !== 0 || !isElfSymbolData(symbol)))) return null;
  const section = opts.sections.find(entry => entry.index === sectionIndex);
  if (opts.sections.length && !section) return null;
  if (section && !hasDataAddress(section, opts)) return null;
  const start = opts.fileType === 1 && section ? section.addr + symbol.value : symbol.value;
  const end = start + (symbol.size === 0n ? 1n : symbol.size);
  if (symbol.size < 0n || start < 0n || end > (opts.is64Bit
    ? 0x1_0000_0000_0000_0000n : 0x1_0000_0000n)) return null;
  if (section && (start < section.addr || end > section.addr + section.size)) {
    issues.push(`Data symbol ${symbol.name || "(unnamed)"} extends outside its section; ignored.`);
    return null;
  }
  if (!section && !elfVirtualRange(opts.programHeaders, start, end - start, fileSize)) return null;
  return { start, end };
};

export const collectElfCodeExclusions = (
  opts: AnalyzeElfInstructionSetOptions, fileSize: number, issues: string[]
): CodeExclusion[] => {
  const ranges: CodeExclusion[] = [];
  for (const symbol of [...opts.dynSymbols?.importSymbols ?? [],
    ...opts.dynSymbols?.exportSymbols ?? []]) {
    const range = symbolRange(symbol, symbol.shndx, symbol.type, opts, fileSize, issues);
    if (range) ranges.push(range);
  }
  for (const table of opts.symbolTables ?? []) {
    for (const symbol of table.entries) {
      const range = symbolRange(symbol, symbol.sectionIndex, symbol.info & 15,
        opts, fileSize, issues);
      if (range) ranges.push(range);
    }
  }
  // GLOB_DAT/JUMP_SLOT write one address to a GOT cell, not executable instructions.
  // x86 psABI relocations; AAELF64 dynamic relocations (1025/1026).
  // https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
  const pointerRelocations = opts.machine === 183 ? [1025, 1026] : [6, 7];
  for (const entry of opts.relocations?.entries ?? []) {
    const width = opts.is64Bit ? 8n : 4n;
    if (opts.fileType === 1 || !pointerRelocations.includes(entry.type ?? -1) || !elfVirtualRange(
      opts.programHeaders, entry.offset, width, fileSize)) continue;
    ranges.push({ start: entry.offset, end: entry.offset + width });
  }
  return ranges;
};
