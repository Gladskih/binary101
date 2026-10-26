export interface CodeViewInlineAnnotation { opcode: number; operands: number[]; }

export interface CodeViewScopeSymbol {
  kind: "inline" | "thunk" | "with" | "block";
  scopeOffsets?: { parent: number; end: number; next?: number };
  inlinee?: number;
  invocations?: number;
  annotations?: CodeViewInlineAnnotation[];
  location?: { segment: number; offset: number };
  codeLength?: number;
  ordinal?: number;
  adjustment?: number;
  target?: string;
  virtualEntry?: number;
}
