import type { ElfParseResult } from "./types.js";
import type { ElfRelocation } from "./relocation-types.js";
import { elfRelocationTypeName } from "./relocation-names.js";
import { ELF_FILE_TYPE, ELF_SECTION_TYPE, ELF_SECTION_FLAG } from "./abi-constants.js";

export type ElfImportLinkKind = "PLT slot" | "GOT slot" |
  "IFUNC resolver slot" | "Other symbol relocation";

export interface ElfImportLink {
  relocationIndex: number;
  kind: ElfImportLinkKind;
  loadSegments: number[];
  sections: number[];
  relroSegments: number[];
  issues: string[];
}

export interface ElfImportLinkage {
  binding: string;
  links: ElfImportLink[];
  issues: string[];
}

// Processor relocation names and widths: glibc elf.h and psABI relocation tables.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/raw/master/x86-64-ABI/abi.pdf
// https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_dynamic_relocations
const slotMachines = new Map([
  [3, 4n], [40, 4n], [62, 8n], [183, 8n], [243, 0n]
]);

const slotKind = (name: string): ElfImportLinkKind | null => {
  if (name.endsWith("_JUMP_SLOT") || name === "R_386_JMP_SLOT") return "PLT slot";
  if (name.endsWith("_GLOB_DAT")) return "GOT slot";
  if (name.endsWith("_IRELATIVE")) return "IFUNC resolver slot";
  return null;
};

const contains = (start: bigint, size: bigint, address: bigint, width: bigint): boolean =>
  start >= 0n && address >= start && width <= size - (address - start);

const bindingPolicy = (elf: ElfParseResult, issues: string[]): string => {
  if (!elf.dynamic) return "Unknown (no dynamic table)";
  // DT_BIND_NOW, DT_FLAGS/DF_BIND_NOW, DT_FLAGS_1/DF_1_NOW: gABI dynamic section
  // and glibc elf.h. Absence permits lazy binding; the runtime can override it.
  // https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
  const masks = new Map([[24, 0n], [30, 8n], [0x6ffffffb, 1n]]);
  const seen = new Map<number, bigint>();
  let eager = false;
  let invalid = elf.dynamic.terminated === false;
  for (const { tag, value } of elf.dynamic.entries) {
    if (typeof tag !== "number" || !masks.has(tag)) continue;
    if (tag === 24) { eager = true; continue; } // DT_BIND_NOW ignores d_un.
    if ((seen.has(tag) && seen.get(tag) !== value) || value < 0n ||
      value > 0xffffffffn) {
      issues.push(`Invalid or conflicting binding tag ${tag}.`);
      invalid = true;
    }
    seen.set(tag, value);
    eager ||= (value & masks.get(tag)!) !== 0n;
  }
  return invalid ? "Unknown (invalid dynamic metadata)" :
    eager ? "Immediate binding requested" : "Lazy binding permitted";
};

const runtimeTable = (elf: ElfParseResult, entry: ElfRelocation): boolean => {
  const table = elf.relocations?.tables[entry.tableIndex];
  if (!table) return false;
  if (table.sources.some(source => source.startsWith("DT_"))) return true;
  return elf.sections.some(section => section.index === table.symbolTableIndex &&
    section.type === ELF_SECTION_TYPE.DYNSYM) &&
    elf.sections.some(section => section.index === table.sectionIndex &&
      (section.flags & ELF_SECTION_FLAG.ALLOC) !== 0n);
};

const validatePltGot = (elf: ElfParseResult, issues: string[]): void => {
  // DT_PLTGOT=3 is a processor-specific address, not the size/start of every GOT slot.
  // https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
  const addresses = new Set(elf.dynamic?.entries.filter(entry => entry.tag === 3)
    .map(entry => entry.value));
  if (addresses.size > 1) issues.push("DT_PLTGOT records conflicting addresses.");
  for (const address of addresses) {
    if (!elf.programHeaders.some(segment => segment.type === 1 &&
      contains(segment.vaddr, segment.memsz, address, 1n))) {
      issues.push(`DT_PLTGOT address 0x${address.toString(16)} is outside PT_LOAD mappings.`);
    }
  }
};

const describeLink = (elf: ElfParseResult, entry: ElfRelocation,
  relocationIndex: number, kind: ElfImportLinkKind, width: bigint): ElfImportLink => {
  const load = elf.programHeaders.filter(segment => segment.type === 1 &&
    contains(segment.vaddr, segment.memsz, entry.offset, width));
  const issues: string[] = [];
  // PT_LOAD and PF_W: gABI program headers; check the complete write, including address overflow.
  // https://gabi.xinuos.com/elf/07-pheader.html
  if (entry.offset < 0n || entry.offset + width > (1n << BigInt(elf.is64 ? 64 : 32))) {
    issues.push("Target range exceeds the ELF address space.");
  }
  if (!load.length) issues.push("Target range is not contained in a PT_LOAD segment.");
  if (load.length > 1) issues.push("Target range has overlapping PT_LOAD mappings.");
  if (load.length === 1 && !(load[0]!.flags & 2)) {
    issues.push("Target is in a PT_LOAD segment without PF_W.");
  }
  if (kind === "Other symbol relocation") {
    issues.push("Write size is unknown; placement checks cover only the target address.");
  }
  // PT_GNU_RELRO describes intended protection; actual mprotect rounds to runtime pages.
  // https://raw.githubusercontent.com/bminor/glibc/master/elf/dl-reloc.c
  return { relocationIndex, kind, loadSegments: load.map(segment => segment.index),
    sections: elf.sections.filter(section => (section.flags & ELF_SECTION_FLAG.ALLOC) !== 0n &&
      contains(section.addr, section.size, entry.offset, width)).map(section => section.index),
    relroSegments: elf.programHeaders.filter(segment => segment.type === 0x6474e552 &&
      contains(segment.vaddr, segment.memsz, entry.offset, width)).map(segment => segment.index),
    issues };
};

export const analyzeElfImportLinkage = (elf: ElfParseResult): ElfImportLinkage | null => {
  if (elf.header.type !== ELF_FILE_TYPE.EXEC && elf.header.type !== ELF_FILE_TYPE.DYN) return null;
  if (!elf.dynamic && !elf.dynSymbols && !elf.relocations) return null;
  const issues = [...(elf.dynamic?.issues ?? []), ...(elf.relocations?.issues ?? []),
    ...(elf.dynSymbols?.issues ?? []), ...(elf.symbolVersions?.issues ?? [])];
  const links: ElfImportLink[] = [];
  validatePltGot(elf, issues);
  const width = slotMachines.get(elf.header.machine);
  for (const [index, entry] of (elf.relocations?.entries ?? []).entries()) {
    if (!runtimeTable(elf, entry)) continue;
    const name = entry.type == null ? "" : elfRelocationTypeName(elf.header.machine, entry.type);
    const kind = width == null ? null : slotKind(name);
    if (!kind && (!entry.symbol || entry.symbol.sectionIndex !== 0 || entry.type === 0)) continue;
    const link = describeLink(elf, entry, index, kind ?? "Other symbol relocation",
      kind ? width || (elf.is64 ? 8n : 4n) : 1n);
    if (kind !== "IFUNC resolver slot" && kind && (!entry.symbolIndex || !entry.symbol)) {
      link.issues.push("Slot relocation has no decoded symbol reference.");
    }
    if (kind === "IFUNC resolver slot" && entry.symbolIndex !== 0) {
      link.issues.push("IRELATIVE expects symbol index zero.");
    }
    const table = elf.relocations!.tables[entry.tableIndex]!;
    if (kind === "PLT slot" && !table.sources.includes("DT_JMPREL")) {
      link.issues.push("PLT slot is not identified by DT_JMPREL.");
    }
    links.push(link);
  }
  return { binding: bindingPolicy(elf, issues), links, issues: [...new Set(issues)] };
};
