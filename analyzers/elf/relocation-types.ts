import type { ElfParseResult } from "./types.js";

export type ElfRelocationImage = Pick<ElfParseResult,
  "header" | "sections" | "programHeaders" | "is64" | "littleEndian" | "fileSize">;
export type ElfRelocationEncoding = "REL" | "RELA" | "RELR";

export interface ElfRelocationTable {
  offset: number;
  size: number;
  entrySize: number;
  encoding: ElfRelocationEncoding;
  sources: string[];
  sectionIndex: number | null;
  symbolTableIndex: number | null;
  targetSectionIndex: number | null;
}

export interface ElfRelocationSymbol {
  name: string;
  value: bigint;
  sectionIndex: number;
}

export interface ElfRelocationTarget {
  sectionIndex: number | null;
  sectionOffset: bigint | null;
  fileOffset: bigint | null;
}

export interface ElfRelocation {
  tableIndex: number;
  recordOffset: number;
  offset: bigint;
  type: number | null;
  symbolIndex: number | null;
  symbol: ElfRelocationSymbol | null;
  addend: bigint | null;
  target: ElfRelocationTarget | null;
}

export interface ElfRelocationInfo {
  tables: ElfRelocationTable[];
  entries: ElfRelocation[];
  issues: string[];
}
