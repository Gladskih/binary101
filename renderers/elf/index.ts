"use strict";

import { dd, rowFlags, rowOpts, safe } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import {
  ELF_CLASS,
  ELF_DATA,
  ELF_TYPE,
  ELF_MACHINE,
  PROGRAM_TYPES,
  SECTION_TYPES,
  SECTION_FLAGS
} from "../../analyzers/elf/constants.js";
import type {
  ElfOptionEntry,
  ElfParseResult,
  ElfProgramHeader,
  ElfSectionHeader
} from "../../analyzers/elf/types.js";
import { renderInstructionSets } from "./disassembly.js";

const mapOptions = (options: ElfOptionEntry[]): Array<[number, string]> =>
  options.map(([code, label]) => [code, label]);

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
  out.push(dd("Class", rowOpts(elf.ident.classByte, mapOptions(ELF_CLASS))));
  out.push(dd("Data", rowOpts(elf.ident.dataByte, mapOptions(ELF_DATA))));
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
  out.push(dd("Type", rowOpts(h.type, mapOptions(ELF_TYPE))));
  out.push(dd("Machine", rowOpts(h.machine, mapOptions(ELF_MACHINE))));
  out.push(dd("Entry", formatHex(h.entry, elf.is64 ? 16 : 8)));
  const phText = `${h.phnum} entries @ ${formatHex(h.phoff, elf.is64 ? 16 : 8)}`;
  const shText = `${h.shnum} entries @ ${formatHex(h.shoff, elf.is64 ? 16 : 8)}`;
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
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Type</th><th>Offset</th><th>VirtAddr</th>` +
      `<th>FileSz</th><th>MemSz</th><th>Flags</th><th>Align</th>` +
    `</tr></thead><tbody>`
  );
  const pad = elf.is64 ? 16 : 8;
  const programTypeOpts = mapOptions(PROGRAM_TYPES);
  elf.programHeaders.forEach((ph: ElfProgramHeader) => {
    const typeLabel =
      ph.typeName || rowOpts(ph.type, programTypeOpts) || safe(`0x${ph.type.toString(16)}`);
    const flags = formatList(ph.flagNames);
    out.push(
      `<tr><td>${ph.index}</td><td>${typeLabel}</td>` +
        `<td>${formatHex(ph.offset, pad)}</td>` +
        `<td>${formatHex(ph.vaddr, pad)}</td>` +
        `<td>${formatHex(ph.filesz, pad)}</td>` +
        `<td>${formatHex(ph.memsz, pad)}</td>` +
        `<td>${flags}</td><td>${safe(ph.align.toString())}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</section>`);
}

function renderSectionHeaders(elf: ElfParseResult, out: string[]): void {
  if (!elf.sections?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Section headers</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Offset</th>` +
      `<th>Size</th><th>Addr</th><th>Flags</th><th>Align</th>` +
    `</tr></thead><tbody>`
  );
  const pad = elf.is64 ? 16 : 8;
  const sectionTypeOpts = mapOptions(SECTION_TYPES);
  elf.sections.forEach((sec: ElfSectionHeader) => {
    const typeLabel =
      sec.typeName || rowOpts(sec.type, sectionTypeOpts) || safe(`0x${sec.type.toString(16)}`);
    const flagsMask = typeof sec.flags === "bigint" ? Number(sec.flags & 0xffffffffn) : sec.flags;
    const flags = rowFlags(flagsMask, SECTION_FLAGS);
    out.push(
      `<tr><td>${sec.index}</td><td>${safe(sec.name || "")}</td>` +
        `<td>${typeLabel}</td><td>${formatHex(sec.offset, pad)}</td>` +
        `<td>${formatHex(sec.size, pad)}</td>` +
        `<td>${formatHex(sec.addr, pad)}</td>` +
        `<td>${flags}</td><td>${safe(sec.addralign.toString())}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</section>`);
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
