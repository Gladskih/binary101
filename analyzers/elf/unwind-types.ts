import type { DwarfCfiInstruction } from "../dwarf/frame-types.js";
import type { DwarfCfiExpression } from "../dwarf/cfi-state-types.js";
export interface ElfUnwindPointer {
  address: bigint;
  indirect: boolean;
}

export type ElfCfiInstruction = DwarfCfiInstruction<DwarfCfiExpression>;

export interface ElfUnwindCie {
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
  instructions: ElfCfiInstruction[];
}

export interface ElfUnwindFde {
  offset: number;
  cieOffset: number;
  start: ElfUnwindPointer | null;
  range: bigint;
  lsda: ElfUnwindPointer | null;
  instructions: ElfCfiInstruction[];
}

export interface ElfUnwindSection {
  sectionIndex: number;
  cies: ElfUnwindCie[];
  fdes: ElfUnwindFde[];
  issues: string[];
}
