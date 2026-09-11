export interface ArmEhabiInstruction { offset: number; text: string }
export interface ArmEhabiProgram { instructions: ArmEhabiInstruction[]; issues: string[] }
export interface ArmEhabiDescriptor {
  kind: "cleanup" | "catch" | "exception specification";
  start: number;
  length: number;
  landingPad?: bigint;
  referenceCatch?: boolean;
  types: number[];
}
export interface ArmEhabiEntry {
  offset: number;
  functionAddress: bigint | null;
  data: number;
  tableAddress?: bigint;
  personality?: number | bigint;
  instructions: ArmEhabiInstruction[];
  descriptors?: ArmEhabiDescriptor[];
  issues: string[];
}
export interface ArmEhabiTable { source: string; entries: ArmEhabiEntry[]; issues: string[] }
