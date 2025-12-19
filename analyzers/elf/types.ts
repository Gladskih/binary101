"use strict";

import type { ElfInstructionSetReport } from "./disassembly-model.js";

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
  is64: boolean;
  littleEndian: boolean;
  fileSize: number;
}
