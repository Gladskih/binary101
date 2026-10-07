import type { DwarfFormValue } from "./types.js";

export type DwarfMacroEntry = { offset: number; opcode: number; operands: DwarfFormValue[] };
export type DwarfMacroUnit = {
  sectionName: string;
  offset: number;
  version: number | null;
  format: 32 | 64;
  lineOffset: bigint | null;
  entries: DwarfMacroEntry[];
};
export type DwarfMacroHeader = {
  version: number | null;
  format: 32 | 64;
  lineOffset: bigint | null;
  operandForms: Map<number, number[]>;
};
