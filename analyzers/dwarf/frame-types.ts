import type { DwarfExpressionOperation } from "./types.js";

export type DwarfCfiInstruction<Value = DwarfExpressionOperation[]> = {
  offset: number;
  operation: string;
  operands: Array<bigint | Value>;
};
export type DwarfFrameEncoding = {
  addressSize: number;
  segmentSize: number;
  codeAlignment: bigint;
  dataAlignment: bigint;
  returnRegister: bigint;
};
export type DwarfFrameCie = {
  offset: number;
  version: number;
  augmentation: string;
  encoding: DwarfFrameEncoding | null;
  instructions: DwarfCfiInstruction[];
};
export type DwarfFrameFde = {
  offset: number;
  cieOffset: number;
  start: bigint;
  segment: bigint | null;
  range: bigint;
  instructions: DwarfCfiInstruction[];
};
export type DwarfFrames = { cies: DwarfFrameCie[]; fdes: DwarfFrameFde[] };
