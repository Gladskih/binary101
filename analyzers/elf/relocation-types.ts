import type { ElfParseResult } from "./types.js";

export type ElfRelocationImage = Pick<ElfParseResult,
  "header" | "sections" | "programHeaders" | "is64" | "littleEndian" | "fileSize" | "dynSymbols">;
export type ElfRelocationEncoding = "REL" | "RELA" | "RELR" |
  "ANDROID_REL" | "ANDROID_RELA" | "CREL" | "AUTH_RELR";

export interface ElfRelocationTable {
  offset: number;
  size: number;
  entrySize: number;
  encoding: ElfRelocationEncoding;
  sources: string[];
  sectionIndex: number | null;
  symbolTableIndex: number | null;
  targetSectionIndex: number | null;
  compressed?: true;
  complete?: boolean;
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
  // Physical file offset, or decoded-section offset when table.compressed is set.
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
