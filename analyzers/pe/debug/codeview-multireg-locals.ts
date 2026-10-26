import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewLocalVariable } from "./codeview-local-types.js";

interface MultiRegisterLayout {
  typeBytes: 2 | 4;
  countOffset: number;
  registerBytes: 1 | 2;
  attributeOffset?: number;
}

// MANYREG arrays store most-significant registers first; MANYREG2 widens both
// the count and register IDs. Managed/attributed forms prepend CV_lvar_attr.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3195
const LAYOUTS = new Map<number, MultiRegisterLayout>([
  [0x000c, { typeBytes: 2, countOffset: 6, registerBytes: 1 }],
  ...[0x1005, 0x110a].map(type => [type, { typeBytes: 4, countOffset: 8, registerBytes: 1 }] as const),
  ...[0x1014, 0x1117].map(type => [type, { typeBytes: 4, countOffset: 8, registerBytes: 2 }] as const),
  ...[0x1025, 0x1121].map(type =>
    [type, { typeBytes: 4, countOffset: 16, registerBytes: 1, attributeOffset: 8 }] as const),
  ...[0x1027, 0x1123, 0x1131].map(type =>
    [type, { typeBytes: 4, countOffset: 16, registerBytes: 2, attributeOffset: 8 }] as const)
]);

export const readCodeViewMultiRegisterLocal = async (reader: LegacyCodeViewReader, type: number
): Promise<{ local: CodeViewLocalVariable; nameOffset: number } | null> => {
  const layout = LAYOUTS.get(type);
  if (!layout) return null;
  const prefix = await reader.view(4, layout.countOffset + layout.registerBytes - 4);
  const count = layout.registerBytes === 1 ? prefix.getUint8(layout.countOffset - 4)
    : prefix.getUint16(layout.countOffset - 4, true);
  const start = layout.countOffset + layout.registerBytes;
  const fields = await reader.view(start, count * layout.registerBytes);
  const registers = Array.from({ length: count }, (_, index) => layout.registerBytes === 1
    ? fields.getUint8(index) : fields.getUint16(index * 2, true));
  const local: CodeViewLocalVariable = { typeIndex: layout.typeBytes === 2
    ? prefix.getUint16(0, true) : prefix.getUint32(0, true), location: { kind: "registers", registers } };
  if (layout.attributeOffset !== undefined) {
    local.firstLiveAddress = { offset: prefix.getUint32(layout.attributeOffset - 4, true),
      section: prefix.getUint16(layout.attributeOffset, true) };
    local.flags = prefix.getUint16(layout.attributeOffset + 2, true);
  }
  return { local, nameOffset: start + fields.byteLength };
};
