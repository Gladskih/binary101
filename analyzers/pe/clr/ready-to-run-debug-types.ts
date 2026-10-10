export interface ReadyToRunDebugBound {
  nativeOffset: number;
  // cordebuginfo.h: -3 epilog, -2 prolog, -1 unmapped; otherwise an IL byte offset.
  ilOffset: number;
  source: number;
}

export type ReadyToRunVariableLocation =
  | { kind: "register" | "register-byref" | "fp-register"; register: number }
  | { kind: "stack" | "stack-byref" | "stack-pair"; baseRegister: number; offset: number }
  | { kind: "register-pair"; register1: number; register2: number }
  | { kind: "register-stack" | "stack-register"; register: number; baseRegister: number; offset: number }
  | { kind: "fp-stack"; index: number }
  | { kind: "varargs"; offset: number };

export interface ReadyToRunDebugVariable {
  startOffset: number;
  endOffset: number;
  // -1 varargs handle, -2 return buffer, -3 generic context, -4 unknown implicit argument.
  variableNumber: number;
  location: ReadyToRunVariableLocation;
}

export interface ReadyToRunDebugMethod {
  runtimeFunctionIndex: number;
  bounds: ReadyToRunDebugBound[];
  variables: ReadyToRunDebugVariable[];
}
