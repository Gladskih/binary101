"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
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

const formatHex = (value: bigint | number, width?: number): string => {
  if (typeof value === "bigint") {
    const hex = value.toString(16);
    const pad = width ? hex.padStart(width, "0") : hex;
    return `0x${pad}`;
  }
  return toHex32(value, width || 0);
};

const formatList = (values: string[] | null | undefined): string =>
  values && values.length ? safe(values.join(", ")) : "-";

const formatMaybeHumanSize = (value: bigint): string => {
  const num = Number(value);
  if (Number.isSafeInteger(num) && num >= 0) {
    return `<span title="${safe(formatHex(value))}">${safe(formatHumanSize(num))}</span>`;
  }
  return safe(formatHex(value));
};

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

function renderOverview(elf: ElfParseResult, out: string[]): void {
  const bits = elf.is64 ? "64-bit" : "32-bit";
  const endian = elf.littleEndian ? "little-endian" : "big-endian";
  const machine = elf.header.machineName || `machine ${elf.header.machine}`;
  const type = elf.header.typeName || `type ${elf.header.type}`;
  const entry = formatHex(elf.header.entry, elf.is64 ? 16 : 8);
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
  out.push(dd("Entry", formatHex(h.entry)));
  const phText = `${h.phnum} entries @ ${formatHex(h.phoff)}`;
  const shText = `${h.shnum} entries @ ${formatHex(h.shoff)}`;
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
    const flags = formatList(ph.flagNames);
    out.push(
      `<tr><td>${ph.index}</td><td><span title="${safe(typeTitle)}">${safe(typeLabel)}</span></td>` +
        `<td>${safe(formatHex(ph.offset))}</td>` +
        `<td>${safe(formatHex(ph.vaddr))}</td>` +
        `<td>${formatMaybeHumanSize(ph.filesz)}</td>` +
        `<td>${formatMaybeHumanSize(ph.memsz)}</td>` +
        `<td>${flags}</td><td>${safe(formatHex(ph.align))}</td></tr>`
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
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show section headers (${elf.sections.length})</summary>`
  );
  out.push(`<div class="tableWrap">`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Offset</th>` +
      `<th>Size</th><th>Addr</th><th>Flags</th><th>Align</th>` +
    `</tr></thead><tbody>`
  );
  const sectionTypeMap = new Map<number, ElfOptionEntry>(SECTION_TYPES.map(entry => [entry[0], entry]));
  elf.sections.forEach((sec: ElfSectionHeader) => {
    const opt = sectionTypeMap.get(sec.type);
    const typeLabel = sec.typeName || opt?.[1] || `0x${sec.type.toString(16)}`;
    const typeTitle = opt?.[2] ? `${typeLabel} - ${opt[2]}` : typeLabel;
    const hint = sec.name ? knownSectionName(sec.name) : null;
    const nameCell = hint
      ? `<span title="${safe(hint)}"><b>${safe(sec.name)}</b></span>`
      : safe(sec.name || "");
    const flags = formatList(sec.flagNames);
    out.push(
      `<tr><td>${sec.index}</td><td>${nameCell}</td>` +
        `<td><span title="${safe(typeTitle)}">${safe(typeLabel)}</span></td><td>${safe(formatHex(sec.offset))}</td>` +
        `<td>${formatMaybeHumanSize(sec.size)}</td>` +
        `<td>${safe(formatHex(sec.addr))}</td>` +
        `<td>${flags}</td><td>${safe(formatHex(sec.addralign))}</td></tr>`
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
  renderInstructionSets(elf, out);
  renderProgramHeaders(elf, out);
  renderSectionHeaders(elf, out);
  renderIssues(elf, out);
  return out.join("");
}
