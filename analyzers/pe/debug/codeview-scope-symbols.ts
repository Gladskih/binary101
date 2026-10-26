import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewScopeSymbol } from "./codeview-scope-types.js";
import { readCodeViewInlineAnnotations } from "./codeview-inline-annotations.js";

interface ScopeLayout { kind: CodeViewScopeSymbol["kind"]; nameOffset: number; width: 2 | 4; }
// WITHSYM16/32, THUNKSYM16/32, BLOCKSYM16 and INLINESITESYM/2; offsets include the record header.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3452
const LAYOUTS = new Map<number, ScopeLayout>([
  [0x106, { kind: "thunk", nameOffset: 23, width: 2 }],
  [0x206, { kind: "thunk", nameOffset: 25, width: 4 }],
  [0x1102, { kind: "thunk", nameOffset: 25, width: 4 }],
  [0x108, { kind: "with", nameOffset: 18, width: 2 }],
  [0x208, { kind: "with", nameOffset: 22, width: 4 }],
  [0x1104, { kind: "with", nameOffset: 22, width: 4 }],
  [0x107, { kind: "block", nameOffset: 18, width: 2 }],
  [0x114d, { kind: "inline", nameOffset: 16, width: 4 }],
  [0x115d, { kind: "inline", nameOffset: 20, width: 4 }]
]);

const fixedScope = (fields: DataView, layout: ScopeLayout): CodeViewScopeSymbol => {
  const scope: CodeViewScopeSymbol = { kind: layout.kind,
    scopeOffsets: { parent: fields.getUint32(0, true), end: fields.getUint32(4, true) } };
  if (layout.kind === "inline") {
    scope.inlinee = fields.getUint32(8, true);
    if (layout.nameOffset === 20) scope.invocations = fields.getUint32(12, true);
  } else if (layout.kind === "thunk") {
    scope.scopeOffsets!.next = fields.getUint32(8, true);
    scope.location = { offset: layout.width === 2 ? fields.getUint16(12, true) : fields.getUint32(12, true),
      segment: fields.getUint16(12 + layout.width, true) };
    scope.codeLength = fields.getUint16(14 + layout.width, true);
    scope.ordinal = fields.getUint8(16 + layout.width);
  } else {
    scope.codeLength = layout.width === 2 ? fields.getUint16(8, true) : fields.getUint32(8, true);
    scope.location = { offset: layout.width === 2 ? fields.getUint16(10, true) : fields.getUint32(12, true),
      segment: fields.getUint16(8 + 2 * layout.width, true) };
  }
  return scope;
};

const nameAt = (reader: LegacyCodeViewReader, type: number, offset: number) =>
  type >= 0x1100 ? reader.utf8Name(offset) : reader.pascal(offset);

// cvdump C7Thunk16Sym/C7Thunk32Sym: adjustor and vcall variants both use signed shorts.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L4580
const thunkVariant = async (reader: LegacyCodeViewReader, type: number,
  start: number, scope: CodeViewScopeSymbol): Promise<void> => {
  if (scope.ordinal === 1) {
    scope.adjustment = (await reader.view(start, 2)).getInt16(0, true);
    scope.target = (await nameAt(reader, type, start + 2)).name;
  } else if (scope.ordinal === 2) scope.virtualEntry = (await reader.view(start, 2)).getInt16(0, true);
  else if (scope.ordinal! > 6) reader.warn(`Unknown CodeView thunk ordinal ${scope.ordinal}.`);
  else if (scope.ordinal! >= 3 && start < reader.size) reader.warn("CodeView thunk variant payload is not interpreted.");
};

export const readCodeViewScopeSymbol = async (reader: LegacyCodeViewReader,
  type: number): Promise<{ name?: string; scope: CodeViewScopeSymbol } | null> => {
  const layout = LAYOUTS.get(type);
  if (!layout) return null;
  const result: { name?: string; scope: CodeViewScopeSymbol } = { scope: { kind: layout.kind } };
  try {
    result.scope = fixedScope(await reader.view(4, layout.nameOffset - 4), layout);
    if (layout.kind === "inline") result.scope.annotations = await readCodeViewInlineAnnotations(reader, layout.nameOffset);
    else {
      const name = await nameAt(reader, type, layout.nameOffset);
      result.name = name.name;
      if (layout.kind === "thunk") await thunkVariant(reader, type, name.end, result.scope);
    }
  } catch (error) { reader.warn(`CodeView lexical scope: ${String(error)}`); }
  return result;
};
