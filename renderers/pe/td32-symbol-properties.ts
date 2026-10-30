import type { Td32SymbolMetadata, Td32SymbolRecord } from "../../analyzers/pe/debug/td32-symbol-types.js";

const KINDS = new Map<number, string>([
  [1, "Compiler"], [2, "Register variable"], [3, "Constant"], [4, "User-defined type"], [5, "Symbol search"],
  [6, "Scope end"], [9, "Object file"], [0x20, "Procedure reference"], [0x21, "Data reference"],
  [0x24, "Uses declarations"], [0x25, "Namespace"], [0x26, "Using declarations"], [0x27, "Property constant"],
  [0x200, "Stack variable"], [0x201, "Local data"], [0x202, "Global data"], [0x203, "Public symbol"],
  [0x204, "Local procedure"], [0x205, "Global procedure"], [0x206, "Thunk"], [0x207, "Lexical block"],
  [0x208, "With scope"], [0x209, "Label"], [0x210, "Entry location"], [0x211, "Optimized location"],
  [0x212, "Procedure epilogue"], [0x213, "Saved registers"]
]);

export const td32SymbolKind = (type: number): string => KINDS.get(type) ?? `Unrecognized symbol kind ${type}`;
export const td32SymbolName = (names: readonly string[], index: number | undefined): string => index === undefined
  ? "(name not stored)" : index === 0 ? "(unnamed)" : names[index - 1] ?? `(unresolved name #${index})`;

export const td32SymbolPlacement = (metadata: Td32SymbolMetadata): string => {
  if (metadata.location) return `segment ${metadata.location.segment}, stored offset ${metadata.location.offset}`;
  if (metadata.frameOffset !== undefined) return `stored BP-relative offset ${metadata.frameOffset} (frame base unresolved)`;
  if (metadata.register !== undefined) return `register #${metadata.register}`;
  return "not stored";
};

const flagProperties = (record: Td32SymbolRecord): string[] => {
  const flags = record.metadata!.flags;
  if (flags === undefined) return [];
  if (record.type !== 4) return [`producer flags 0x${flags.toString(16)}`];
  const result: string[] = [];
  if (flags & 1) result.push("tag declaration");
  if (flags & 2) result.push("nested type");
  if (flags & ~3) result.push(`unknown properties 0x${(flags & ~3).toString(16)}`);
  return result;
};

export const td32SymbolProperties = (record: Td32SymbolRecord, names: readonly string[]): string => {
  const metadata = record.metadata!;
  const result = flagProperties(record);
  if (metadata.value !== undefined) result.push(`value ${metadata.value}`);
  if (metadata.usingCount !== undefined) result.push(`${metadata.usingCount} declared using entries`);
  if (metadata.ordinal !== undefined) result.push(["standard", "adjustor", "virtual call", "pcode"][metadata.ordinal]
    ?? `unknown thunk ordinal ${metadata.ordinal}`);
  if (metadata.adjustment !== undefined) result.push(`this adjustment ${metadata.adjustment}`);
  if (metadata.targetNameIndex !== undefined) result.push(`target ${td32SymbolName(names, metadata.targetNameIndex)}`);
  if (record.type === 3) result.push("numeric value layout unresolved");
  return result.join("; ") || "none";
};
