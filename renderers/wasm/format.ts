import type { WasmExternal, WasmInstruction, WasmLimits, WasmType } from "../../analyzers/wasm/types.js";

export const SECTION_NAMES: Readonly<Record<number, string>> = {
  0: "Custom", 1: "Type", 2: "Import", 3: "Function", 4: "Table", 5: "Memory", 6: "Global",
  7: "Export", 8: "Start", 9: "Element", 10: "Code", 11: "Data", 12: "Data count", 13: "Tag"
};

export const formatSignature = (type: WasmType | undefined): string =>
  type ? `(${type.params.join(", ")}) → (${type.results.join(", ")})` : "Unresolved type";

export const formatLimits = (limits: WasmLimits): string =>
  `${limits.min}..${limits.max ?? "unbounded"}, ${limits.address64 ? "64" : "32"}-bit` +
  (limits.shared ? ", shared" : "");

export const formatDescriptor = (descriptor: WasmExternal): string => {
  switch (descriptor.kind) {
    case "function": case "tag": return `type ${descriptor.typeIndex}`;
    case "table": return `${descriptor.table.type}, ${formatLimits(descriptor.table.limits)}`;
    case "memory": return formatLimits(descriptor.limits);
    case "global": return `${descriptor.global.type}, ${descriptor.global.mutable ? "mutable" : "constant"}`;
  }
};

export const formatExpression = (expression: WasmInstruction[]): string =>
  expression.map(instruction => `${instruction.mnemonic} ${instruction.operands}`.trim()).join("; ");
