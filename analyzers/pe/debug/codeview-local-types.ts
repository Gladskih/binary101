export type CodeViewVariableLocation =
  | { kind: "register"; register: number }
  | { kind: "frameRelative"; offset: number }
  | { kind: "registerRelative"; register: number; offset: number }
  | { kind: "registerOffset"; register: number; offset: number }
  | { kind: "program"; program: number };

export interface CodeViewLocalVariable {
  typeIndex: number;
  flags?: number;
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
  range?: { offset: number; section: number; length: number };
  gaps: { offset: number; length: number }[];
}
