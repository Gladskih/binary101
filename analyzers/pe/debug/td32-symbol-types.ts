export interface Td32SymbolMetadata {
  typeIndex?: number;
  location?: { offset: number; segment: number };
  codeLength?: number;
  debugRange?: { start: number; end: number };
  scopeOffsets?: { parent: number; end: number; next?: number };
  frameOffset?: number;
  register?: number;
  flags?: number;
  value?: string;
  nameIndices?: number[];
  usingCount?: number;
  rangeStart?: number;
  ordinal?: number;
  adjustment?: number;
  targetNameIndex?: number;
}

export interface Td32SymbolRecord {
  type: number;
  nameIndex?: number;
  compiler?: string;
  metadata?: Td32SymbolMetadata;
}
