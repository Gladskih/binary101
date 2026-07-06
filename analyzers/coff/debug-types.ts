"use strict";

export interface CoffDebugHeader {
  numberOfSymbols: number;
  lvaToFirstSymbol: number;
  numberOfLineNumbers: number;
  lvaToFirstLineNumber: number;
  rvaToFirstByteOfCode: number;
  rvaToLastByteOfCode: number;
  rvaToFirstByteOfData: number;
  rvaToLastByteOfData: number;
}

export type CoffAuxiliaryRecord =
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

export interface CoffSymbol {
  index: number;
  name: string;
  nameSource: "short" | "string-table" | "unresolved";
  stringTableOffset?: number;
  value: number;
  sectionNumber: number;
  type: number;
  storageClass: number;
  auxiliarySymbolCount: number;
  auxiliaryRecords: CoffAuxiliaryRecord[];
}

export interface CoffLineNumber {
  symbolTableIndexOrVirtualAddress: number;
  lineNumber: number;
}

export interface CoffLineNumberBlock {
  offset: number;
  sectionIndex?: number;
  sectionName?: string;
  records: CoffLineNumber[];
}

export interface CoffDebugInfo {
  source: "debug-directory" | "coff-header";
  header?: CoffDebugHeader;
  symbolTableOffset: number;
  stringTableOffset: number | null;
  stringTableSize?: number;
  symbols: CoffSymbol[];
  lineNumberBlocks: CoffLineNumberBlock[];
  warnings?: string[];
}

export type CoffStringTable = {
  offset: number;
  readableSize: number;
  resolve: (stringTableOffset: number) => Promise<{ value: string; warning?: string }>;
};
