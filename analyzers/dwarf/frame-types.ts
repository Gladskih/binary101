import type { DwarfExpressionOperation } from "./types.js";

export type DwarfCfiInstruction<Value = DwarfExpressionOperation[]> = {
  offset: number;
  operation: string;
  operands: Array<bigint | Value>;
};
export type DwarfCfiProgram<Value = DwarfExpressionOperation[]> = {
  instructions: DwarfCfiInstruction<Value>[];
  instructionsIncomplete?: true;
};
export type DwarfFrameEncoding = {
  addressSize: number;
  segmentSize: number;
  codeAlignment: bigint;
  dataAlignment: bigint;
  returnRegister: bigint;
};
export type DwarfFrameCie = DwarfCfiProgram & {
  offset: number;
  version: number;
  augmentation: string;
  encoding: DwarfFrameEncoding | null;
};
export type DwarfFrameFde = DwarfCfiProgram & {
  offset: number;
  cieOffset: number;
  start: bigint;
  segment: bigint | null;
  range: bigint;
};
export type DwarfFrames = { cies: DwarfFrameCie[]; fdes: DwarfFrameFde[] };
