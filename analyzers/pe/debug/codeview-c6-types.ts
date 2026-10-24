export type CodeViewC6ScalarBase = { kind: "type"; index: number } | { kind: "style"; value: string };

export type CodeViewC6Type =
  | { kind: "array"; bitLength: string; elementType: number; indexType?: number }
  | { kind: "structure"; bitLength: string; fieldCount: string; typeList?: number; nameList?: number; packing?: number }
  | { kind: "scalar"; bitLength: string; base: CodeViewC6ScalarBase;
    range?: { base: CodeViewC6ScalarBase; lower: string; upper: string } }
  | { kind: "pointer"; typeIndex: number; style?: number }
  | { kind: "bitfield"; bitLength: string; style: number; position: number }
  | { kind: "procedure"; returnType?: number; returnLeaf?: number;
    callingConvention: number; parameterCount: string; argumentsType: number };
