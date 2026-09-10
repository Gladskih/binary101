export interface ElfMipsAbiFlags {
  version: number; isaLevel: number; isaRevision: number; gprSize: number;
  cpr1Size: number; cpr2Size: number; fpAbi: number; isaExtension: number;
  ases: number; flags1: number; flags2: number;
}
export interface ElfMipsRegInfo { gprMask: number; cprMasks: number[]; gpValue: bigint }
export interface ElfMipsOption { kind: number; section: number; info: number; registerInfo?: ElfMipsRegInfo }
export interface ElfMipsMetadata {
  source: string;
  abiFlags?: ElfMipsAbiFlags;
  registerInfo?: ElfMipsRegInfo;
  options?: ElfMipsOption[];
  issues: string[];
}
