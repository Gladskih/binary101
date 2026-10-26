export type CodeViewVariableLocation =
  | { kind: "register"; register: number }
  | { kind: "registers"; registers: number[] }
  | { kind: "slot"; slot: number }
  | { kind: "groupShared"; slot: number; offset: number }
  | { kind: "shaderRegister"; registerType: number; attributes: number; registerOffsets?: number[] }
  | { kind: "frameRelative"; offset: number }
  | { kind: "registerRelative"; register: number; offset: number }
  | { kind: "registerOffset"; register: number; offset: number }
  | { kind: "registerIndirectOffset"; register: number; offset: number; memberOffset: number }
  | { kind: "registerIndirectRelative"; register: number; offset: number; memberOffset: number }
  | { kind: "program"; program: number };

export interface CodeViewLocalVariable {
  typeIndex: number;
  flags?: number;
  firstLiveAddress?: { offset: number; section: number };
  moduleOffset?: number;
  location?: CodeViewVariableLocation;
}

export interface CodeViewFrame {
  frameBytes: number;
  paddingBytes: number;
  paddingOffset: number;
  savedRegisterBytes: number;
  handler: { offset: number; section: number };
  flags: number;
}

export interface CodeViewLocalRange {
  location: CodeViewVariableLocation;
  attributes?: number;
  parentOffset?: number;
  sizeInParent?: number;
  range?: { offset: number; section: number; length: number };
  gaps: { offset: number; length: number }[];
}
