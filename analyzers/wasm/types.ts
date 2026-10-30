export type WasmLimits = { min: bigint; max: bigint | null; shared: boolean; address64: boolean };
export type WasmType = { params: string[]; results: string[] };
export type WasmTable = { type: string; limits: WasmLimits };
export type WasmGlobalType = { type: string; mutable: boolean };
export type WasmExternal =
  | { kind: "function"; typeIndex: number }
  | { kind: "table"; table: WasmTable }
  | { kind: "memory"; limits: WasmLimits }
  | { kind: "global"; global: WasmGlobalType }
  | { kind: "tag"; typeIndex: number };
export type WasmImport = { module: string; name: string; descriptor: WasmExternal };
export type WasmExport = { name: string; kind: string; index: number };
export type WasmInstruction = { offset: number; mnemonic: string; operands: string };
export type WasmCode = {
  offset: number; size: number; locals: { count: number; type: string }[];
  instructions: WasmInstruction[];
};
export type WasmSection = {
  id: number; offset: number; payloadOffset: number; size: number; customName?: string;
  status: "decoded" | "partial" | "opaque";
};
export type WasmData = {
  mode: string; memory: number | null; expression: WasmInstruction[];
  offset: number; size: number; preview: number[];
};
export type WasmElement = {
  mode: string; table: number | null; expression: WasmInstruction[];
  type: string; entries: (number | WasmInstruction[])[];
};
export type WasmParseResult = {
  fileSize: number; version: number | null; sections: WasmSection[];
  types: WasmType[]; imports: WasmImport[]; functions: { typeIndex: number }[];
  tables: WasmTable[]; memories: WasmLimits[];
  globals: { descriptor: WasmGlobalType; expression: WasmInstruction[] }[];
  exports: WasmExport[]; start: number | null; elements: WasmElement[];
  code: WasmCode[]; data: WasmData[]; dataCount: number | null; tags: number[];
  moduleName: string | null; functionNames: Record<number, string>;
  producers: { field: string; name: string; version: string }[];
  features: { prefix: string; name: string }[]; issues: string[];
};
