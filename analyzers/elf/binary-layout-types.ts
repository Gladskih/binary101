export type ElfByteOrder = "little" | "big";

export interface ElfSymbolRecord {
  nameOffset: number;
  value: bigint;
  size: bigint;
  info: number;
  other: number;
  sectionIndex: number;
}

export interface ElfSymbolicRelocationRecord {
  offset: bigint;
  type: number;
  symbolIndex: number;
  addend: bigint | null;
}

export interface ElfBinaryLayout {
  byteOrder: ElfByteOrder;
  wordSize: number;
  dynamicEntrySize: number;
  symbolEntrySize: number;
  readWord: (view: DataView) => bigint | null;
  readDynamic: (view: DataView) => { tag: bigint; value: bigint } | null;
  readSymbol: (view: DataView) => ElfSymbolRecord | null;
  readSectionIndex: (view: DataView) => number | null;
  supportsSymbolicRelocations: (machine: number) => boolean;
  relocations: Record<"REL" | "RELA", {
    entrySize: number;
    read: (view: DataView) => ElfSymbolicRelocationRecord | null;
  }>;
}
