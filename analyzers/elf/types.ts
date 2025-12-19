"use strict";

import type { ElfInstructionSetReport } from "./disassembly-types.js";

export type ElfOptionEntry = [number, string, string?];

export interface ElfIdent {
  classByte: number;
  className: string;
  dataByte: number;
  dataName: string;
  osabi: number;
  abiVersion: number;
}

export interface ElfHeader {
  type: number;
  typeName: string | null;
  machine: number;
  machineName: string | null;
  entry: bigint;
  phoff: bigint;
  shoff: bigint;
  flags: number;
  ehsize: number;
  phentsize: number;
  phnum: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
}

export interface ElfProgramHeader {
  type: number;
  typeName: string | null;
  offset: bigint;
  vaddr: bigint;
  paddr: bigint;
  filesz: bigint;
  memsz: bigint;
  flags: number;
  flagNames: string[];
  align: bigint;
  index: number;
}

export interface ElfSectionHeader {
  nameOff: number;
  type: number;
  typeName: string | null;
  flags: bigint;
  flagNames: string[];
  addr: bigint;
  offset: bigint;
  size: bigint;
  link: number;
  info: number;
  addralign: bigint;
  entsize: bigint;
  index: number;
  name?: string;
}

export interface ElfParseResult {
  ident: ElfIdent;
  header: ElfHeader;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  issues: string[];
  disassembly?: ElfInstructionSetReport;
  interpreter?: ElfInterpreterInfo;
  dynamic?: ElfDynamicInfo;
  dynSymbols?: ElfDynamicSymbolInfo;
  tls?: ElfTlsInfo;
  notes?: ElfNotesInfo;
  comment?: ElfCommentInfo;
  debugLink?: ElfDebugLinkInfo;
  is64: boolean;
  littleEndian: boolean;
  fileSize: number;
}

export interface ElfInterpreterInfo {
  path: string;
  issues: string[];
}

export interface ElfDynamicInfo {
  needed: string[];
  soname: string | null;
  rpath: string | null;
  runpath: string | null;
  init: bigint | null;
  fini: bigint | null;
  preinitArray: { vaddr: bigint; size: bigint } | null;
  initArray: { vaddr: bigint; size: bigint } | null;
  finiArray: { vaddr: bigint; size: bigint } | null;
  flags: number | null;
  flags1: number | null;
  issues: string[];
}

export interface ElfDynamicSymbol {
  index: number;
  name: string;
  value: bigint;
  size: bigint;
  bind: number;
  bindName: string;
  type: number;
  typeName: string;
  visibility: number;
  visibilityName: string;
  shndx: number;
}

export interface ElfDynamicSymbolInfo {
  total: number;
  importSymbols: ElfDynamicSymbol[];
  exportSymbols: ElfDynamicSymbol[];
  issues: string[];
}

export interface ElfTlsInfo {
  segments: Array<{ index: number; offset: bigint; vaddr: bigint; filesz: bigint; memsz: bigint; align: bigint }>;
  sections: Array<{ index: number; name: string; addr: bigint; offset: bigint; size: bigint; flags: string[] }>;
}

export interface ElfNoteEntry {
  source: string;
  name: string;
  type: number;
  typeName: string | null;
  description: string | null;
  value: string | null;
  descSize: number;
}

export interface ElfNotesInfo {
  entries: ElfNoteEntry[];
  issues: string[];
}

export interface ElfCommentInfo {
  strings: string[];
  issues: string[];
}

export interface ElfDebugLinkInfo {
  fileName: string;
  crc32: number | null;
  issues: string[];
}
