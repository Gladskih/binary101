import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface CodeViewFieldReferences {
  typeIndex?: number;
  attributes?: number;
  methodCount?: number;
  virtualBasePointer?: number;
  vtableOffset?: number;
}
interface CodeViewFieldLayout extends CodeViewFieldReferences { size: number }

// Offsets from the leaf tag, without a record length. lfMember[_16t], lfBClass,
// lfVBClass, lfMethod, lfNestType[Ex], lfOneMethod, lfVFuncTab/Off and lfEnumerate.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const LAYOUTS = new Map<number, CodeViewFieldLayout>([
  [0x400, { size: 6, typeIndex: 2, attributes: 4 }],
  [0x401, { size: 8, typeIndex: 2, virtualBasePointer: 4, attributes: 6 }],
  [0x402, { size: 8, typeIndex: 2, virtualBasePointer: 4, attributes: 6 }],
  [0x403, { size: 4, attributes: 2 }], [0x404, { size: 4, typeIndex: 2 }],
  [0x406, { size: 6, typeIndex: 2, attributes: 4 }], [0x407, { size: 6, typeIndex: 2, attributes: 4 }],
  [0x408, { size: 6, methodCount: 2, typeIndex: 4 }], [0x409, { size: 4, typeIndex: 2 }],
  [0x40a, { size: 4, typeIndex: 2 }], [0x40b, { size: 4, typeIndex: 2 }],
  [0x40c, { size: 6, attributes: 2, typeIndex: 4 }], [0x40d, { size: 8, typeIndex: 2, vtableOffset: 4 }],
  [0x1400, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x1401, { size: 12, attributes: 2, typeIndex: 4, virtualBasePointer: 8 }],
  [0x1402, { size: 12, attributes: 2, typeIndex: 4, virtualBasePointer: 8 }],
  [0x1403, { size: 8, typeIndex: 4 }], [0x1405, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x1406, { size: 8, attributes: 2, typeIndex: 4 }], [0x1407, { size: 8, methodCount: 2, typeIndex: 4 }],
  [0x1408, { size: 8, typeIndex: 4 }], [0x1409, { size: 8, typeIndex: 4 }],
  [0x140a, { size: 8, typeIndex: 4 }], [0x140b, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x140c, { size: 12, typeIndex: 4, vtableOffset: 8 }],
  [0x140d, { size: 8, attributes: 2, typeIndex: 4 }], [0x140e, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x1502, { size: 4, attributes: 2 }], [0x150c, { size: 8, typeIndex: 4 }],
  [0x150d, { size: 8, attributes: 2, typeIndex: 4 }], [0x150e, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x150f, { size: 8, methodCount: 2, typeIndex: 4 }], [0x1510, { size: 8, typeIndex: 4 }],
  [0x1511, { size: 8, attributes: 2, typeIndex: 4 }], [0x1512, { size: 8, attributes: 2, typeIndex: 4 }],
  [0x1513, { size: 8, attributes: 2, typeIndex: 4 }], [0x151a, { size: 8, attributes: 2, typeIndex: 4 }]
]);

export const readCodeViewFieldPrefix = async (
  reader: LegacyCodeViewReader, type: number
): Promise<CodeViewFieldReferences> => {
  const layout = LAYOUTS.get(type);
  if (!layout) return {};
  const view = await reader.view(0, layout.size);
  const fields: CodeViewFieldReferences = {};
  for (const key of ["typeIndex", "virtualBasePointer"] as const) {
    const offset = layout[key];
    if (offset !== undefined) fields[key] = type < 0x1000 ? view.getUint16(offset, true) : view.getUint32(offset, true);
  }
  if (layout.attributes !== undefined) {
    fields.attributes = view.getUint16(layout.attributes, true);
    if (fields.attributes & ~0x3ff) reader.warn("CodeView field has unknown attribute bits.");
  }
  if (layout.methodCount !== undefined) fields.methodCount = view.getUint16(layout.methodCount, true);
  if (layout.vtableOffset !== undefined) fields.vtableOffset = view.getInt32(layout.vtableOffset, true);
  return fields;
};
