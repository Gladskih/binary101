export interface ElfCoreField { name: string; value: bigint | string }
export interface ElfCoreMapping { start: bigint; end: bigint; pageOffset: bigint; path: string }
export interface ElfCoreNote {
  fields: ElfCoreField[];
  registers?: ElfCoreField[];
  auxv?: { tag: bigint; value: bigint }[];
  mappings?: ElfCoreMapping[];
  issues: string[];
}
