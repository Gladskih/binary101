import type { DwarfCfiInstruction, DwarfCfiProgram } from "../dwarf/frame-types.js";
import type { DwarfCfiExpression } from "../dwarf/cfi-state-types.js";
export interface ElfUnwindPointer {
  address: bigint;
  indirect: boolean;
}

export type ElfCfiInstruction = DwarfCfiInstruction<DwarfCfiExpression>;

export interface ElfUnwindCie extends DwarfCfiProgram<DwarfCfiExpression> {
  offset: number;
  version: number;
  augmentation: string;
  addressSize: number;
  codeAlignment: bigint;
  dataAlignment: bigint;
  returnRegister: bigint;
  fdeEncoding: number;
  lsdaEncoding: number;
  personality: ElfUnwindPointer | null;
}

export interface ElfUnwindFde extends DwarfCfiProgram<DwarfCfiExpression> {
  offset: number;
  cieOffset: number;
  start: ElfUnwindPointer | null;
  range: bigint;
  lsda: ElfUnwindPointer | null;
}

export interface ElfUnwindSection {
  sectionIndex: number;
  cies: ElfUnwindCie[];
  fdes: ElfUnwindFde[];
  issues: string[];
}
