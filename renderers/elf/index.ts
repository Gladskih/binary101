"use strict";

import { dd, rowOpts, safe } from "../../html-utils.js";
import {
  ELF_CLASS,
  ELF_DATA,
  ELF_TYPE,
  ELF_MACHINE,
  PROGRAM_TYPES,
  SECTION_TYPES
} from "../../analyzers/elf/constants.js";
import type {
  ElfOptionEntry,
  ElfParseResult,
  ElfProgramHeader,
  ElfSectionHeader
} from "../../analyzers/elf/types.js";
import { renderInstructionSets } from "./disassembly.js";
import { renderElfDebug } from "./debug.js";
import { renderElfLinking } from "./linking.js";
import { renderElfNotes } from "./notes.js";
import { renderElfSymbols } from "./symbols.js";
import { renderElfTls } from "./tls.js";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "./value-format.js";

const SECTION_HINTS: Record<string, string> = {
  ".text": "Executable code (instructions).",
  ".plt": "Procedure linkage table (PLT). Usually small trampolines for dynamic linking.",
  ".got": "Global offset table (GOT). Runtime-resolved addresses for position-independent code.",
  ".got.plt": "GOT entries used by PLT stubs for lazy binding.",
  ".dynsym": "Dynamic symbol table (exports/imports for the dynamic loader).",
  ".dynstr": "Strings for the dynamic symbol table.",
  ".dynamic": "Dynamic linking tags (DT_*).",
  ".rela.plt": "Relocations applied to PLT/GOT entries (with addends).",
  ".rel.plt": "Relocations applied to PLT/GOT entries (no addends).",
  ".rela.dyn": "Relocations applied at load time (with addends).",
  ".rel.dyn": "Relocations applied at load time (no addends).",
  ".eh_frame": "Unwind info for stack unwinding (exceptions/backtraces).",
  ".eh_frame_hdr": "Index into .eh_frame to accelerate unwinding.",
  ".init": "Initialization code (legacy).",
  ".fini": "Finalization code (legacy).",
  ".init_array": "Array of constructors (function pointers) run at startup.",
  ".fini_array": "Array of destructors (function pointers) run at exit.",
  ".preinit_array": "Early constructors run before .init_array."
};

const knownSectionName = (name: string): string | null => SECTION_HINTS[name.toLowerCase()] || null;

const SHT_RELA = 4;
const SHT_DYNAMIC = 6;
const SHT_REL = 9;
const SHT_SYMTAB = 2;
const SHT_DYNSYM = 11;
const SHT_GROUP = 17;

const sectionIndexWithName = (sectionsByIndex: Map<number, ElfSectionHeader>, index: number): string => {
  if (index === 0) return "0 (SHN_UNDEF)";
  const section = sectionsByIndex.get(index);
  if (!section) return `${index} (missing section)`;
  return section.name ? `${index} (${section.name})` : `${index}`;
};

const sectionLinkMeaning = (section: ElfSectionHeader): string => {
  switch (section.type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
      return "sh_link points to the string table used by this symbol table.";
    case SHT_REL:
    case SHT_RELA:
      return "sh_link points to the symbol table used by relocations in this section.";
    case SHT_DYNAMIC:
      return "sh_link usually points to the dynamic string table (.dynstr).";
    default:
      return "sh_link is section-type specific auxiliary data.";
  }
};

const sectionInfoMeaning = (section: ElfSectionHeader): string => {
  switch (section.type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
      return "sh_info stores one greater than the last local symbol index.";
    case SHT_REL:
    case SHT_RELA:
      return "sh_info points to the section that relocations apply to.";
    case SHT_GROUP:
      return "sh_info stores the symbol-table index of the group signature symbol.";
    default:
      return "sh_info meaning depends on section type and flags.";
  }
};

const formatSectionLink = (section: ElfSectionHeader, sectionsByIndex: Map<number, ElfSectionHeader>): string => {
  const label = sectionIndexWithName(sectionsByIndex, section.link);
  return `<span title="${safe(sectionLinkMeaning(section))}">${safe(label)}</span>`;
};

const formatSectionInfo = (section: ElfSectionHeader, sectionsByIndex: Map<number, ElfSectionHeader>): string => {
  if (section.type === SHT_SYMTAB || section.type === SHT_DYNSYM) {
    const text = `${section.info} (symbol index after last local symbol)`;
    return `<span title="${safe(sectionInfoMeaning(section))}">${safe(text)}</span>`;
  }
  if (section.type === SHT_REL || section.type === SHT_RELA) {
    const text = sectionIndexWithName(sectionsByIndex, section.info);
    return `<span title="${safe(sectionInfoMeaning(section))}">${safe(text)}</span>`;
  }
  return `<span title="${safe(sectionInfoMeaning(section))}">${safe(String(section.info))}</span>`;
};

const formatSectionEntSize = (section: ElfSectionHeader): string => {
  if (section.entsize === 0n) {
    return `<span title="sh_entsize: 0 means variable-sized data or a non-table section.">0</span>`;
  }
  const value = formatElfMaybeHumanSize(section.entsize);
  return `<span title="sh_entsize: fixed size of one entry in this section table.">${value}</span>`;
};

function renderOverview(elf: ElfParseResult, out: string[]): void {
  const bits = elf.is64 ? "64-bit" : "32-bit";
  const endian = elf.littleEndian ? "little-endian" : "big-endian";
  const machine = elf.header.machineName || `machine ${elf.header.machine}`;
  const type = elf.header.typeName || `type ${elf.header.type}`;
  const entry = formatElfHex(elf.header.entry, elf.is64 ? 16 : 8);
  out.push(`<section>`);
  out.push(
    `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Big picture</h4>`
  );
  const summary =
    `${bits} ${endian} ELF ${safe(type)} targeting ${safe(machine)}. ` +
    `Entry point at ${entry}. Program and section headers describe how the loader maps ` +
    `segments and named sections into memory.`;
  out.push(`<div class="smallNote">${summary}</div>`);
  out.push(`</section>`);
}

function renderIdent(elf: ElfParseResult, out: string[]): void {
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Identification</h4>`);
  out.push(`<dl>`);
  out.push(dd("Class", rowOpts(elf.ident.classByte, ELF_CLASS)));
  out.push(dd("Data", rowOpts(elf.ident.dataByte, ELF_DATA)));
  out.push(dd("OS ABI", safe(elf.ident.osabi)));
  out.push(dd("ABI version", safe(elf.ident.abiVersion)));
  out.push(`</dl>`);
  out.push(`</section>`);
}

function renderHeader(elf: ElfParseResult, out: string[]): void {
  const h = elf.header;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ELF header</h4>`);
  out.push(`<dl>`);
  out.push(dd("Type", rowOpts(h.type, ELF_TYPE)));
  out.push(dd("Machine", rowOpts(h.machine, ELF_MACHINE)));
  out.push(dd("Entry", formatElfHex(h.entry)));
  const phText = `${h.phnum} entries @ ${formatElfHex(h.phoff)}`;
  const shText = `${h.shnum} entries @ ${formatElfHex(h.shoff)}`;
  out.push(dd("Program headers", phText));
  out.push(dd("Section headers", shText));
  out.push(dd("Header size", `${h.ehsize} bytes`));
  out.push(dd("PH entry size", `${h.phentsize} bytes`));
  out.push(dd("SH entry size", `${h.shentsize} bytes`));
  out.push(`</dl>`);
  out.push(`</section>`);
}

function renderProgramHeaders(elf: ElfParseResult, out: string[]): void {
  if (!elf.programHeaders?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Program headers</h4>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show program headers (${elf.programHeaders.length})</summary>`
  );
  out.push(`<div class="tableWrap">`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Type</th><th>Offset</th><th>VirtAddr</th>` +
      `<th>FileSz</th><th>MemSz</th><th>Flags</th><th>Align</th>` +
    `</tr></thead><tbody>`
  );
  const programTypeMap = new Map<number, ElfOptionEntry>(PROGRAM_TYPES.map(entry => [entry[0], entry]));
  elf.programHeaders.forEach((ph: ElfProgramHeader) => {
    const opt = programTypeMap.get(ph.type);
    const typeLabel = ph.typeName || opt?.[1] || `0x${ph.type.toString(16)}`;
    const typeTitle = opt?.[2] ? `${typeLabel} - ${opt[2]}` : typeLabel;
    const flags = formatElfList(ph.flagNames);
    out.push(
      `<tr><td>${ph.index}</td><td><span title="${safe(typeTitle)}">${safe(typeLabel)}</span></td>` +
        `<td>${safe(formatElfHex(ph.offset))}</td>` +
        `<td>${safe(formatElfHex(ph.vaddr))}</td>` +
        `<td>${formatElfMaybeHumanSize(ph.filesz)}</td>` +
        `<td>${formatElfMaybeHumanSize(ph.memsz)}</td>` +
        `<td>${flags}</td><td>${safe(formatElfHex(ph.align))}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</div></details></section>`);
}

function renderSectionHeaders(elf: ElfParseResult, out: string[]): void {
  if (!elf.sections?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Section headers</h4>`);
  out.push(
    `<div class="smallNote"><span class="mono">sh_link</span> is section-type specific, ` +
      `<span class="mono">sh_info</span> meaning depends on section type, and ` +
      `<span class="mono">sh_entsize</span> is the fixed record size (0 for variable/non-table data).</div>`
  );
  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show section headers (${elf.sections.length})</summary>`
  );
  out.push(`<div class="tableWrap">`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Offset</th>` +
      `<th>Size</th><th>Addr</th><th>Flags</th><th>Align</th>` +
      `<th title="sh_link: section index reference with type-specific meaning.">Link</th>` +
      `<th title="sh_info: extra data with type-specific meaning.">Info</th>` +
      `<th title="sh_entsize: size of one fixed-size entry in table-like sections.">EntSize</th>` +
    `</tr></thead><tbody>`
  );
  const sectionTypeMap = new Map<number, ElfOptionEntry>(SECTION_TYPES.map(entry => [entry[0], entry]));
  const sectionsByIndex = new Map<number, ElfSectionHeader>(elf.sections.map(section => [section.index, section]));
  elf.sections.forEach((sec: ElfSectionHeader) => {
    const opt = sectionTypeMap.get(sec.type);
    const typeLabel = sec.typeName || opt?.[1] || `0x${sec.type.toString(16)}`;
    const typeTitle = opt?.[2] ? `${typeLabel} - ${opt[2]}` : typeLabel;
    const hint = sec.name ? knownSectionName(sec.name) : null;
    const nameCell = hint
      ? `<span title="${safe(hint)}"><b>${safe(sec.name)}</b></span>`
      : safe(sec.name || "");
    const flags = formatElfList(sec.flagNames);
    out.push(
      `<tr><td>${sec.index}</td><td>${nameCell}</td>` +
        `<td><span title="${safe(typeTitle)}">${safe(typeLabel)}</span></td><td>${safe(formatElfHex(sec.offset))}</td>` +
        `<td>${formatElfMaybeHumanSize(sec.size)}</td>` +
        `<td>${safe(formatElfHex(sec.addr))}</td>` +
        `<td>${flags}</td><td>${safe(formatElfHex(sec.addralign))}</td>` +
        `<td>${formatSectionLink(sec, sectionsByIndex)}</td>` +
        `<td>${formatSectionInfo(sec, sectionsByIndex)}</td>` +
        `<td>${formatSectionEntSize(sec)}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</div></details></section>`);
}

function renderIssues(elf: ElfParseResult, out: string[]): void {
  if (!elf.issues?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  elf.issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
}

export function renderElf(elf: ElfParseResult | null): string {
  if (!elf) return "";
  const out: string[] = [];
  renderOverview(elf, out);
  renderIdent(elf, out);
  renderHeader(elf, out);
  renderElfLinking(elf, out);
  renderElfSymbols(elf, out);
  renderElfTls(elf, out);
  renderElfNotes(elf, out);
  renderElfDebug(elf, out);
  renderInstructionSets(elf, out);
  renderProgramHeaders(elf, out);
  renderSectionHeaders(elf, out);
  renderIssues(elf, out);
  return out.join("");
}
