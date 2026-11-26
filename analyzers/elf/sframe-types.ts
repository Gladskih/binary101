export interface ElfSFrameHeader {
  abi: number;
  fixedFpOffset: number;
  fixedRaOffset: number;
  auxSize: number;
  functionCount: number;
  rowCount: number;
  rowBytes: number;
  functionOffset: number;
  rowOffset: number;
}

export interface ElfSFrameFunction {
  offset: number;
  startOffset: bigint;
  size: number;
  rowOffset: number;
  attributes?: { rowCount: number; info: number; info2?: number; repeatSize?: number };
  issues: string[];
}

export interface ElfSFrameRow {
  functionIndex: number;
  pcOffset: number;
  info: number;
  words: number[];
}

export interface ElfSFrame {
  source: { sectionIndex: number } | { programHeaderIndex: number };
  address: bigint | null;
  preamble?: { version: number; flags: number };
  header?: ElfSFrameHeader;
  functions: ElfSFrameFunction[];
  rows: ElfSFrameRow[];
  issues: string[];
}
