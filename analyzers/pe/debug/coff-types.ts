"use strict";

export interface PeCoffDebugHeader {
  numberOfSymbols: number;
  lvaToFirstSymbol: number;
  numberOfLineNumbers: number;
  lvaToFirstLineNumber: number;
  rvaToFirstByteOfCode: number;
  rvaToLastByteOfCode: number;
  rvaToFirstByteOfData: number;
  rvaToLastByteOfData: number;
}

export type PeCoffAuxiliaryRecord =
  | {
      kind: "function-definition";
      tagIndex: number;
      totalSize: number;
      pointerToLineNumber: number;
      pointerToNextFunction: number;
    }
  | { kind: "begin-end-function"; lineNumber: number; pointerToNextFunction: number }
  | { kind: "weak-external"; tagIndex: number; characteristics: number }
  | { kind: "file"; fileName: string }
  | {
      kind: "section-definition";
      length: number;
      numberOfRelocations: number;
      numberOfLineNumbers: number;
      checkSum: number;
      number: number;
      selection: number;
    }
  | { kind: "raw"; bytes: number[] };

export interface PeCoffSymbol {
  index: number;
  name: string;
  nameSource: "short" | "string-table" | "unresolved";
  stringTableOffset?: number;
  value: number;
  sectionNumber: number;
  type: number;
  storageClass: number;
  auxiliarySymbolCount: number;
  auxiliaryRecords: PeCoffAuxiliaryRecord[];
}

export interface PeCoffLineNumber {
  symbolTableIndexOrVirtualAddress: number;
  lineNumber: number;
}

export interface PeCoffLineNumberBlock {
  offset: number;
  sectionIndex?: number;
  sectionName?: string;
  records: PeCoffLineNumber[];
}

export interface PeCoffDebugInfo {
  source: "debug-directory" | "coff-header";
  header?: PeCoffDebugHeader;
  symbolTableOffset: number;
  stringTableOffset: number | null;
  stringTableSize?: number;
  symbols: PeCoffSymbol[];
  lineNumberBlocks: PeCoffLineNumberBlock[];
  warnings?: string[];
}

export type PeCoffStringTable = {
  offset: number;
  readableSize: number;
  resolve: (stringTableOffset: number) => Promise<{ value: string; warning?: string }>;
};

// Microsoft PE/COFF: IMAGE_COFF_SYMBOLS_HEADER is eight DWORDs.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_coff_symbols_header
export const IMAGE_COFF_SYMBOLS_HEADER_SIZE = 32;
// Microsoft PE/COFF: IMAGE_SYMBOL records are fixed 18-byte entries.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
export const IMAGE_SYMBOL_SIZE = 18;
// Microsoft PE/COFF: COFF line-number entries are fixed 6-byte records.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-line-numbers-deprecated
export const IMAGE_LINENUMBER_SIZE = 6;
