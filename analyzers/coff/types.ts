"use strict";

import type { CoffDebugInfo } from "./debug-types.js";

export type CoffSectionName =
  | { kind: "inline"; value: string }
  | { kind: "coff-string-table"; value: string; offset: number };

export interface CoffFileHeader {
  Machine: number;
  NumberOfSections: number;
  TimeDateStamp: number;
  PointerToSymbolTable: number;
  NumberOfSymbols: number;
  SizeOfOptionalHeader: number;
  Characteristics: number;
}

export interface CoffSection {
  name: CoffSectionName;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  pointerToRelocations?: number;
  pointerToLinenumbers?: number;
  numberOfRelocations?: number;
  numberOfLinenumbers?: number;
  characteristics: number;
  entropy?: number | null;
}

export interface CoffRelocation {
  index: number;
  virtualAddress: number;
  symbolTableIndex: number;
  type: number;
}

export interface CoffRelocationBlock {
  offset: number;
  sectionIndex: number;
  sectionName: string;
  records: CoffRelocation[];
  extendedRelocationCount?: number;
  warnings?: string[];
}

export interface CoffObjectParseResult {
  signature: "COFF";
  header: CoffFileHeader;
  sections: CoffSection[];
  relocations?: CoffRelocationBlock[];
  coffStringTableSize?: number;
  coffDebug?: CoffDebugInfo;
  warnings?: string[];
}
